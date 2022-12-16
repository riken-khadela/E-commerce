from driver.driver import get_driver,driver_option
from selenium.webdriver.common.by import By
import random, time, requests
from webdriver_manager.chrome import ChromeDriverManager
from selenium import webdriver  

def random_sleep(a=5,b=9):
    time.sleep(random.randint(a,b))
    
def my_scheduled_job():
    driver =webdriver.Chrome(ChromeDriverManager().install())
    driver.maximize_window()
    driver.get('https://in.puma.com/in/en/mens')
    product_li = []
    random_sleep()

    product_cards = driver.find_elements(By.CSS_SELECTOR, "div.row.product-grid.no-gutters div[data-grid-tile-wrapper]")
    titles = driver.find_elements(By.XPATH, '//*[@id="product-list-items"]/li[1]/div[3]/a/h3')[0].text

    count_ = 0
    while True:
        product = []
        try: 
        
            count_ += 1
            img_ele = driver.find_element(By.XPATH,f'//*[@id="product-list-items"]/li[{count_}]/div[1]/a/div[1]/img')
            img_link = img_ele.get_attribute('src')
            description = driver.find_elements(By.XPATH, f'//*[@id="product-list-items"]/li[{count_}]/div[3]/a/h3')[0].text
            price = driver.find_elements(By.XPATH,f'//*[@id="product-list-items"]/li[{count_}]/div[3]/div/span[1]')[0].text
            if count_%20 == 0:
                driver.execute_script("return arguments[0].scrollIntoView();", img_ele)
                random_sleep()
            data = {
                    "Name" : description,
                    "ImgLink" : img_link,
                    "Price" : int(str(price).strip().replace('₹','').replace(',',''))
                }
            response = requests.post('http://127.0.0.1:8000/api/product/',data=data).json()
            
        except Exception as e:
                img_ele = driver.find_element(By.XPATH,f'//*[@id="product-list-items"]/li[{count_-1}]/div[1]/a/div[1]/img')
                driver.execute_script("return arguments[0].scrollIntoView();", img_ele)
                random_sleep()
            
        if count_ == 1000:
            break
        
my_scheduled_job()