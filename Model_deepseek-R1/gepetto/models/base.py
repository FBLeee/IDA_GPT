import abc

GPT3_MODEL_NAME = "deepseek-ai/DeepSeek-R1"
GPT4_MODEL_NAME = "deepseek-ai/DeepSeek-R1"

class LanguageModel(abc.ABC):
    @abc.abstractmethod
    def query_model_async(self, query, cb):
        pass


def get_model(model):
    """
    Instantiates a model based on its name
    :param model: The model to use
    :param config: The object containing the configuration of the program
    :return:
    """
    if model == GPT3_MODEL_NAME or model == GPT4_MODEL_NAME:
        from gepetto.models.openai import GPT
        return GPT(model)
    else:
        print(f"Warning:  {model} does not exist! Using default model ({GPT3_MODEL_NAME}).")
        from gepetto.models.openai import GPT
        return GPT(GPT3_MODEL_NAME)
