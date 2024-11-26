import unittest
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy

import string
import random
import time

# Import Appium UiAutomator2 driver for Android platforms (AppiumOptions)
from appium.options.android import UiAutomator2Options

capabilities = dict(
    platformName='Android',
    automationName='uiautomator2',
    deviceName='Google Pixel',
    appPackage='org.thoughtcrime.securesms',
#    appActivity='.RoutingActivity',
    noReset=True,
    autoLaunch=False,
    language='en',
    locale='US'
)

appium_server_url = 'http://localhost:4723'

# Converts capabilities to AppiumOptions instance
capabilities_options = UiAutomator2Options().load_capabilities(capabilities)

class TestAppium(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = webdriver.Remote(command_executor=appium_server_url,options=capabilities_options)

    def tearDown(self) -> None:
        if self.driver:
            self.driver.quit()

    def test_find_battery(self) -> None:
        time.sleep(10)
#        el = self.driver.find_element(by=AppiumBy.XPATH, value='//*[@text="sven"]')
#        el.click()
        el = self.driver.find_element(by=AppiumBy.XPATH, value='//*[@text="Signal message"]')
        el.click()
        for i in range(0, 128):
            print("=============================================================================== Message " + str(i));
            el.send_keys(''.join(random.choices(string.ascii_uppercase + string.digits, k=111)))
            self.driver.press_keycode(66)
            time.sleep(5)
        self.driver.back()

if __name__ == '__main__':
    unittest.main()
