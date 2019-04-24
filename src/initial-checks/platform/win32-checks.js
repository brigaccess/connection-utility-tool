const wlan = require("node-winwlanapi-status");
const fw = require("node-winfirewall");
const sec = require("node-wscapi");

const result = require('../check-result');

const WIFI_ACTIVE = wlan.WIFI_CONNECTED || wlan.WIFI_AD_HOC_NETWORK_FORMED;

exports.wifiCheck = async function() {
    var ifaces = wlan.getWirelessStatus();
    var status = result.PASSED;
    if (ifaces.length != 0) {
        var ifacesEnabled = ifaces.map((iface) =>
            (iface.state & WIFI_ACTIVE) !== 0
        ).reduce((p, c) => p || c);

        if (ifacesEnabled)
        {
            status = result.FAILED;
        }
    }
    return {status};
}

function checkPortsFor(ports, port) {
    if (ports === null) return false;

    // Check port ranges
    var portRangeRegex = /(\d+)\s*[\-]\s*(\d+)/g;
    var portRange;
    while ((portRange = portRangeRegex.exec(ports)) !== null) {
        var start = Number.parseInt(portRange[1]);
        var end = Number.parseInt(portRange[2]);
        if (start <= port && end >= port) {
            return true;
        }
    }

    // Check individual ports
    ports.replace(/\s/, '');
    if (!ports.startsWith(',')) ports = ',' + ports;
    if (!ports.endsWith(',')) ports += ',';

    return ports.indexOf(',' + String(port) + ',') != -1;
}

function checkWindowsFirewallRules() {
    var rules = fw.getFirewallRules();
    var mdnsRules = [];
    rules.map((rule) => {
        if (rule.enabled && (checkPortsFor(rule.localPorts, 5353) || checkPortsFor(rule.remotePorts, 5353)) &&
            rule.action != 'Allow')
        {
            return {
                status: result.FAILED,
                details: {
                    rulename: rule.name
                }
            }
        }
    });

    // No need to return any messages here, this check is called from checkFw only
    return {status: result.PASSED}
}

exports.firewallCheck = async function() {
    var products = sec.getSecurityProducts();
    var activeFW = [];
    var windowsFirewallActivated = false;
    products.firewall.map((item) => {
        if (item.state == 0) {
            // Check WF rules separately if it's active
            if (item.remediationPath.endsWith('firewall.cpl')) {
                windowsFirewallActivated = true;
            }
            activeFW.push(item.name);
        }
    });

    if (windowsFirewallActivated) {
        // Check if everything is okay and if not,
        // the check is failed
        var wfcheck = checkWindowsFirewallRules();
        if (wfcheck.status == result.FAILED) {
            return wfcheck;
        }
    }

    if (activeFW.length > 0) {
        return {
            status: result.WARNING,
            details: {
                firewalls: activeFW
            }
        };
    }

    return {status: result.PASSED};
}

exports.antivirusCheck = async function() {
    var products = sec.getSecurityProducts();
    var activeAV = [];
    products.antivirus.map((item) => {
        // Ignore Windows Defender -- we're looking for (potentially) bad guys
        if (item.remediationPath != 'windowsdefender://' && item.state == 0) {
            activeAV.push(item.name);
        }
    });

    if (activeAV.length > 0) {
        return {
            status: result.INFO,
            details: {
                antiviruses: activeAV
            }
        };
    }
    return {status: result.PASSED};
}

// TODO Anti-spyware checks?