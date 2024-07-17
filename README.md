# XORInsertionPoint Burp Extension

_By [Nick Coblentz](https://www.linkedin.com/in/ncoblentz/)_

__The XORInsertionPoint Burp Extension is made possible by [Virtue Security](https://www.virtuesecurity.com), the Application Penetration Testing consulting company I work for.__

## About

The __XORInsertionPoint Burp Extension__ was created to facilitate scanning parameters in an application that obfuscated all database IDs by XORing the database ID by 0x74 and then Base64 encoding the result. I could have gone request by request, identified the obfuscated parameters, decoded them, then use a hackvertor expression for each instance to automatically encode it before sending it to the scanner. But that was very time intensive. Instead, I created this plugin that detected and added a new insertion point for the Burp Scanner that automatically encoded any relevant parameters.

## How to Use It

- Customize the extension with the XOR (or other encoding) operation used by your application
- Build it with `gradlew shadowJar`
- Add the extension in burp from the `build/libs/XORInsertionPoint-x.y-all.jar` folder where `x.y` represents the build version
- Send an item to scanner and it will automatically: look for those relevant parameters decode them, find the base value of the original database ID, and then encode it for each attack payload