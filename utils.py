import configparser
import os

def save_selected_theme(theme_name):
    config = configparser.ConfigParser()
    config['Settings'] = {'theme': theme_name}
    with open('data/settings.ini', 'w') as configfile:
        config.write(configfile)

def load_selected_theme():
    config = configparser.ConfigParser()
    if os.path.exists('data/settings.ini'):
        config.read('data/settings.ini')
        return config.get('Settings', 'theme', fallback='Dark')
    return 'Dark'