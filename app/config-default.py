from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    client_id: str = ""
    client_secret: str = ""
    oauth_token: str = ""
    skills_id: str = ""
    mqtt_broker: str = ""
    mqtt_port: int = 1883
    mqtt_topic: str = "$me/device/#"
    class Config:
        env_file = ".env"

settings = Settings()