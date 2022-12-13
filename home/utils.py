import os
from twilio.rest import Client

class Mobile_verification:

    """
    This Class is normally use for sending OTP in mobile which was used to register new account
    In this class there is credential just for temprerory to use 
    And For More information Please visit "https://www.twilio.com/".
    """
    
    def __init__(self) -> None:
        self.account_sid = "AC3b05a51676ee6eca3e6b72cd5f7d131c"
        self.auth_token = "7181b1ec3ab0ddea60c087ac6c61ccf4"
        self.verify_sid = "VA5af70b81bb163952d768e8f9c7153491"
        self.client = Client(self.account_sid, self.auth_token)
        self.verified_number = ""

    def get_otp(self,verify_number = ""):
        """_summary_
            in this function will take a Mobile number and return Verification status In case of any error it will return False to verify the process is sending OTP is done or not
        Args:
            verify_number (str, optional): _description_. Defaults to "".

        Returns:
            _type_: _description_
        """
        self.verified_number = "+91" + verify_number
        if self.verified_number:
            verification = self.client.verify.v2.services(self.verify_sid) \
            .verifications \
            .create(to=self.verified_number, channel="sms")

            return verification.status
        else:
            return False

    def send_otp(self,otp_code,verify_number):
        """ 
        This will take an OTP which were sent to the Mobile number which was used to send otp and a Mobile number as well.
        """
        self.verified_number = "+91" + verify_number
        verification_check = self.client.verify.v2.services(self.verify_sid) \
        .verification_checks \
        .create(to=self.verified_number, code=otp_code)

        return verification_check.status
    
    
