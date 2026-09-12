from concurrent.futures import ThreadPoolExecutor


class ThreadPoolService:
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def get_executor(self):
        """Get thread pool instance"""
        return self.executor

    def shutdown(self):
        """Shutdown thread pool"""
        self.executor.shutdown(wait=False)


def get_thread_pool_service(max_workers: int = 4) -> ThreadPoolService:
    """Get ThreadPoolService instance (dependency injection)"""
    return ThreadPoolService(max_workers=max_workers)
