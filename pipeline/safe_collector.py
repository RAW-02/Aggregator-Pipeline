class SafeCollector:

    @staticmethod
    def execute(func, default=None):
        try:
            result = func()
            return result, True

        except Exception as e:
            print(e)
            return default, False
