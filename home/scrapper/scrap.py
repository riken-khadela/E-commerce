# import requests
# from bs4 import BeautifulSoup
# import csv

# URL = "https://www.geeksforgeeks.org/data-structures/"
# r = requests.get(URL)
# headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"}
# # Here the user agent is for Edge browser on windows 10. You can find your browser user agent from the above given link.
# r = requests.get(url=URL, headers=headers)

# soup = BeautifulSoup(r.content, 'html5lib') 

# # print(soup.prettify())
# aa = soup.find('div', attrs = {'class':'textwidget'}) 
# print(aa)


from home.scrapper.driver.driver import get_driver


driver = get_driver()

driver.get('https://in.puma.com/in/en/mens')
input('Enter :')
driver.quit()