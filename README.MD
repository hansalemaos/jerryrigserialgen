# jerry-rigged license system with UUID check (preventing more than one installation) and expiration date

### Tested against Python 3.9.16 (Anaconda) -  Windows 10

#### jerry-rigged???

From https://www.urbandictionary.com/define.php?term=jerry-rig
jerry-rig - To put together in a way that works, but is contrary to the "norm" or specific directions (instructions)

The serial number system can be cracked easily (which one can't?), but it should be secure enough for any average user.

### pip install jerryrigserialgen - if you want to generate serial numbers

### pip install jerryrigserialver - if you want to verify serial numbers (client)


```python
from jerryrigserialgen import Serialgenerator, serialgenconfig

# transfer.sh seems to be offline (https://github.com/dutchcoders/transfer.sh/issues/556), that's why i added this:
serialgenconfig.transfershdomain = 'https://temp.sh'

# Generates serial numbers
# pip install jerryrigserialgen
seri = Serialgenerator(
    product="myproduct",  # Name of the product
    savefolder="c:\\mynicefolder\\new",  # just for the record - files are not needed
    hardcodedpasswort_transfer="topsecret",  # for transfer.sh - must be hard-coded in the app the client uses
    hardcodedpasswort_url="5248614597016233",  # 16 digits to encrypt the URL - must be hard-coded in the app the client uses
    addinformationtoserial=(
        "info1",
        "info2",
    ),  # extra information you want to transmit to the app the client uses
    licensedays=17,  # duration of the license - from today on
    subtract_from_time=0,  # for debugging - to create expired licenses
)
serialnumber, debuginfo = seri.upload()
print(serialnumber) # This is the serial number you are going to give to your client, like: 566978376a4b356956775955427a4779636e533856705a59534d314369387735526e59744230396f6c6771795256675a31365a756947344753616d3757536d5961704f736a362f63506871724a792f3845664d4845773d3d475ac18a6927938b4ede1613058f253e


# output
# File written to: c:\mynicefolder\new\2023_03_23_09_23_18_28484401.cfg
# 566978376a4b356956775955427a4779636e533856705a59534d314369387735526e59744230396f6c6771795256675a31365a756947344753616d3757536d5961704f736a362f63506871724a792f3845664d4845773d3d475ac18a6927938b4ede1613058f253e

##########################################################################

# Check serial numbers - client's PC

# pip install jerryrigserialver
from jerryrigserialver import check_serial

isvalid, daysleft, duration_of_license, product, otherinfos = check_serial(
    hardcodedpasswort_transfer="topsecret",
    # hardcodedpasswort_transfer for transfer.sh - must be hard-coded
    hardcodedpasswort_url="5248614597016233",  # 16 digits to encrypt the url - must be hard-coded
    serialnumber=serialnumber,
    notvalidanymore=f"The license you're using is not valid anymore. It expired %d day[s] ago",
    stillvalid=f"The license you're using is valid for %d more day[s].",
    serialusedanotherpc="The license has been used on another PC",
)
print(isvalid, daysleft, duration_of_license, product, otherinfos)


# The license you're using is valid for 17 more day[s].
# True 17 17 myproduct ['info1', 'info2']

# Compile the code of your app using PyInstaller or some other tool
```