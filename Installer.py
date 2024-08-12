import os

# Proje klasörü ve alt klasörleri oluştur
folders = [
    "firewall-rule-analyzer/analyzer",
    "firewall-rule-analyzer/gui",
    "firewall-rule-analyzer/logs",
    "firewall-rule-analyzer/reports",
    "firewall-rule-analyzer/tests"
]

for folder in folders:
    os.makedirs(folder, exist_ok=True)

# Dosya içeriklerini oluştur
files_content = {
    "firewall-rule-analyzer/analyzer/config_parser.py": '''\
class ConfigParser:
    def __init__(self, config_file):
        self.config_file = config_file

    def parse(self):
        rules = []
        with open(self.config_file, 'r') as file:
            for line in file:
                if "allow" in line or "deny" in line:
                    rules.append(line.strip())
        return rules
''',

    "firewall-rule-analyzer/analyzer/rule_analyzer.py": '''\
class RuleAnalyzer:
    def __init__(self, rules):
        self.rules = rules

    def analyze(self):
        findings = []
        for rule in self.rules:
            if "any" in rule:  # Simple check for overly permissive rules
                findings.append(f"Overly permissive rule detected: {rule}")
        return findings
''',

    "firewall-rule-analyzer/analyzer/dns_checker.py": '''\
import dns.resolver

class DNSChecker:
    def __init__(self, hostname):
        self.hostname = hostname

    def resolve(self):
        try:
            return dns.resolver.resolve(self.hostname, 'A')[0].to_text()
        except dns.resolver.NXDOMAIN:
            return None
''',

    "firewall-rule-analyzer/gui/main_window.py": '''\
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Firewall Rule Analyzer')

        self.text_edit = QTextEdit(self)
        self.text_edit.setGeometry(10, 10, 380, 250)

        self.button = QPushButton('Analyze', self)
        self.button.setGeometry(150, 270, 100, 30)
        self.button.clicked.connect(self.analyze)

    def analyze(self):
        # Bu kısımda analiz yapılacak ve sonuç text_edit alanına yazılacak
        self.text_edit.setText('Analysis Complete!')
''',

    "firewall-rule-analyzer/main.py": '''\
from analyzer.config_parser import ConfigParser
from analyzer.rule_analyzer import RuleAnalyzer
from analyzer.dns_checker import DNSChecker
from gui.main_window import MainWindow
from PyQt5.QtWidgets import QApplication
import sys

def main():
    # Config dosyasını oku ve kuralları al
    parser = ConfigParser('firewall_config.txt')
    rules = parser.parse()

    # Kuralları analiz et
    analyzer = RuleAnalyzer(rules)
    findings = analyzer.analyze()

    # DNS kontrolü örneği
    dns_checker = DNSChecker('example.com')
    ip_address = dns_checker.resolve()

    # GUI'yi başlat
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
''',

    "firewall-rule-analyzer/tests/test_config_parser.py": '''\
import unittest
from analyzer.config_parser import ConfigParser

class TestConfigParser(unittest.TestCase):
    def test_parse(self):
        parser = ConfigParser('test_config.txt')
        rules = parser.parse()
        self.assertTrue(len(rules) > 0)
''',

    "firewall-rule-analyzer/tests/test_rule_analyzer.py": '''\
import unittest
from analyzer.rule_analyzer import RuleAnalyzer

class TestRuleAnalyzer(unittest.TestCase):
    def test_analyze(self):
        rules = ['allow any to any', 'deny 192.168.1.1']
        analyzer = RuleAnalyzer(rules)
        findings = analyzer.analyze()
        self.assertTrue(len(findings) > 0)
'''
}

# Dosyaları ilgili klasörlere yazma
for path, content in files_content.items():
    with open(path, 'w') as file:
        file.write(content)

print("Proje yapısı oluşturuldu ve dosyalar ilgili klasörlere yerleştirildi.")

# Gerekli kütüphaneleri yükleme
os.system('pip install flask scapy pyqt5 dnspython')

print("Gerekli Python kütüphaneleri yüklendi.")
