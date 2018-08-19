from burp import IBurpExtender
from burp import ITab
from javax.swing import (
    JPanel,
    JTextField,
    SwingUtilities,
    JLabel,
    SwingConstants,
    JTextArea,
    JComboBox,
    DefaultComboBoxModel,
    JCheckBox,
    JButton
    )
from java.awt import (
    GridBagLayout,
    GridBagConstraints,
    Insets
    )
from java.lang import (
    Object,
    Double
    )

from jarray import array
from exceptions_fix import FixBurpExceptions


panel = JPanel();

class BurpExtender(IBurpExtender, ITab):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("AES CRYPTO")
    
        return

    def buildUI(self):
        return 

        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "DBIN Crypto Plugin"
    
    def getUiComponent(self):
        ui = self.buildUI()
        # add the custom tab to Burp's UI
        self._callbacks.customizeUiComponent(ui)
        return ui
