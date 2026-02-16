from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, target, config, logger):
        self.target = target
        self.config = config
        self.logger = logger
        self.results = []

    @abstractmethod
    def scan(self):
        """
        Perform the scan logic.
        Should populate self.results with findings.
        """
        pass

    def get_results(self):
        """
        Return the list of findings.
        """
        return self.results
