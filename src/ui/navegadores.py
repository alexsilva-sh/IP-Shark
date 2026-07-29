"""Pool de navegadores usado pelas consultas ao IBM X-Force."""
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from queue import Empty, Queue
from threading import Thread

import log
from core.navegador import start_browser

_log = log.obter("pool")


class DriverIndisponivel(Exception):
    def __init__(self, vivos, tamanho):
        self.vivos = vivos
        self.tamanho = tamanho
        super().__init__(f"nenhum navegador disponivel ({vivos}/{tamanho})")


class DriverPool:
    """O tamanho e calibragem medida: 3 sustenta o paralelismo sem disparar o bloqueio
    do X-Force. Esta classe cuida do resto -- boot, timeout e substituicao."""

    TENTATIVAS = 3
    ESPERA_ENTRE_TENTATIVAS = 3
    TIMEOUT_EMPRESTIMO = 120

    def __init__(self, tamanho=3, ao_degradar=None):
        self.tamanho = tamanho
        self.fila = Queue()
        self.todos = []
        self.vivos = 0
        self.ultimo_erro = ""
        self.boot_concluido = threading.Event()
        self._lock = threading.Lock()
        self._ao_degradar = ao_degradar

    def iniciar_async(self):
        Thread(target=self._boot, daemon=True).start()

    def _boot(self):
        # Em paralelo: serial triplicava o tempo ate o pool ficar utilizavel.
        with ThreadPoolExecutor(max_workers=self.tamanho) as executor:
            list(executor.map(self._subir_um, range(self.tamanho)))
        self.boot_concluido.set()
        if self.vivos < self.tamanho and self._ao_degradar:
            self._ao_degradar(self.vivos, self.tamanho, self.ultimo_erro)

    def _subir_um(self, _indice=0):
        for tentativa in range(self.TENTATIVAS):
            try:
                driver = start_browser()
            except Exception as e:
                self.ultimo_erro = str(e)
                _log.warning("tentativa %s de %s de subir navegador falhou: %s",
                             tentativa + 1, self.TENTATIVAS, e)
                if tentativa < self.TENTATIVAS - 1:
                    time.sleep(self.ESPERA_ENTRE_TENTATIVAS)
                continue
            with self._lock:
                self.todos.append(driver)
                self.vivos += 1
            self.fila.put(driver)
            return True
        return False

    @contextmanager
    def emprestar(self):
        """Empresta um driver; levanta DriverIndisponivel em vez de pendurar para sempre."""
        if self.boot_concluido.is_set() and self.vivos == 0:
            raise DriverIndisponivel(0, self.tamanho)
        try:
            driver = self.fila.get(timeout=self.TIMEOUT_EMPRESTIMO)
        except Empty:
            raise DriverIndisponivel(self.vivos, self.tamanho)
        try:
            yield driver
        finally:
            if self._vivo(driver):
                self.fila.put(driver)
            else:
                self._descartar(driver)

    @staticmethod
    def _vivo(driver):
        try:
            driver.window_handles
            return True
        except Exception as e:
            _log.info("navegador morto sera descartado e reposto: %s", type(e).__name__)
            return False

    def _descartar(self, driver):
        """Navegador morto nao volta para a fila: envenenaria toda consulta seguinte."""
        with self._lock:
            self.vivos -= 1
            if driver in self.todos:
                self.todos.remove(driver)
            repor = self.vivos < self.tamanho
        try:
            driver.quit()
        except Exception as e:
            # Esperado: quase sempre ja esta morto, que e o motivo de estar sendo descartado.
            _log.debug("quit() do navegador descartado falhou: %s", type(e).__name__)
        if repor:
            Thread(target=self._subir_um, daemon=True).start()

    def encerrar(self):
        with self._lock:
            drivers = set(self.todos)
            self.todos.clear()
            self.vivos = 0
        while True:
            try:
                drivers.add(self.fila.get_nowait())
            except Empty:
                break
        if not drivers:
            return

        def _quit(d):
            try:
                d.quit()
            except Exception as e:
                _log.debug("quit() no fechamento falhou: %s", type(e).__name__)

        with ThreadPoolExecutor(max_workers=len(drivers)) as executor:
            list(executor.map(_quit, drivers))
