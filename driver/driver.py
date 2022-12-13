from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
# from e_com.settings import BASE_DIR
import time, random, os
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def driver_option(profile_dir='profile'):

    options = webdriver.ChromeOptions()
    # options.add_extension("driver/CyberGhost_VPN.crx")

    options.add_argument("--allow-running-insecure-content")
    options.add_argument("--disable-web-security")
    options.add_argument("disable-infobars")
    options.add_argument('--no-proxy-server')
    options.add_argument('--disable-gpu')
    options.add_argument('log-level=3')
    options.add_argument('--no-sandbox')
    options.add_argument('--autoplay-policy=no-user-gesture-required')
    options.add_argument('--start-maximized')    
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--enable-javascript")
    options.add_argument("--disable-notifications")
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_argument("--enable-popup-blocking")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-setuid-sandbox")
    options.add_argument("--remote-debugging-port=9222")
    options.add_argument("--disable-dev-shm-using")
    options.add_argument("--ignore-certificate-errors-spki-list")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    options.add_experimental_option("excludeSwitches", [
        "enable-logging",
        "enable-automation",
        "ignore-certificate-errors",
        "safebrowsing-disable-download-protection",
        "safebrowsing-disable-auto-update",
        "disable-client-side-phishing-detection"])
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
    prefs = {"credentials_enable_service": True,
             "profile.password_manager_enabled": True}
    options.add_experimental_option("prefs", prefs)
    options.add_argument(f"--user-data-dir={os.path.join(BASE_DIR, 'profiles')}") 
    options.headless = True
    options.add_argument(f'--profile-directory={profile_dir}')

    return options

def get_driver(profile_dir='profile',connect_vpn = False,hide_browser = False) :
    options = driver_option(profile_dir)
    if hide_browser :
        options.headless = True

    driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
    # driver = webdriver.Chrome(executable_path=os.path.join(BASE_DIR, 'driver/chromedriver'), options=options)
    if connect_vpn == True :
        connect_vpn(driver)
    return driver

def connect_vpn(driver):


    driver.switch_to.window(driver.window_handles[0])
    driver.get('chrome-extension://ffbkglfijbcbgblgflchnbphjdllaogb/index.html')
    time.sleep(10)
    try:
        connected_btn = driver.find_element(By.CLASS_NAME, 'connected')
        connected_btn.click() if connected_btn else None
    except Exception as e:...# document.querySelector("body > app-root > main > app-home > div > div.spinner > app-switch > div > div.spinner > div.spinner-inner").click()

    # Select country
    countries_drop_down_btn = driver.find_elements(By.TAG_NAME, 'mat-select-trigger')
    countries_drop_down_btn[0].click() if countries_drop_down_btn else None

    # randomly select a country name from a list
    country_list = ['United States','Romania','Netherlands','Germany']
    vpn_country = random.choice(country_list)

    total_option_country = driver.find_elements(By.TAG_NAME, 'mat-option')
    for i in total_option_country:
        i_id = i.get_attribute('id')
        country_text_ele = i.find_element(By.XPATH, f"//*[@id='{i_id}']/span")
        country_text = country_text_ele.text
        
        # checking if the country is whether same or not and click on it
        if vpn_country == country_text:
            country_text_ele.click()
            break

    # Checking is the VPN connected or not
    try:
        time.sleep(1)
        driver.find_element(By.CLASS_NAME,'disconnected').click()
    except Exception as e:print(e)