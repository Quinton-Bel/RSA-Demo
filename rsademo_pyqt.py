"""
Based on https://gist.github.com/JonCooperWorks/5314103
"""
import secrets
import sys
import math
from PyQt5.Qt import QApplication, QClipboard
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QWidget, QLineEdit, QLabel, QPlainTextEdit, QPushButton, QDesktopWidget, QGroupBox, QGridLayout, QHBoxLayout, QVBoxLayout
from PyQt5.QtCore import QSize, pyqtSlot

# Global instance of SystemRandom (safer than random)
secure_rng = secrets.SystemRandom()

# Miller–Rabin primality test
def isPrime(n, k=10):
    if n == 2:
        return True
    if not n & 1:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1:
            return True
        for i in range(1, s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1

    s = 0
    d = n - 1

    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in range(1, k):
        a = secure_rng.randrange(2, n - 1)
        if not check(a, s, d, n):
            return False
    return True

def generateLargePrime(k):
    # k is the desired bit length
    r = 100 * (math.log(k, 2) + 1)  # number of attempts max
    r_ = r
    while r > 0:
        n = secure_rng.randrange(2**(k-1), 2**(k))
        r -= 1
        if isPrime(n) == True:
            return n

    str_failure = "Failure after" + str(r_) + "tries."
    return str_failure


def gcd(a, b):
    '''
    Euclid's algorithm for determining the greatest common divisor
    Use iteration to make it faster for larger integers
    '''
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return lx

def rwh_primes2(n):
    # https://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    """ Input n>=6, Returns a list of primes, 2 <= p < n """
    correction = (n % 6 > 1)
    n = {0: n, 1: n-1, 2: n+4, 3: n+3, 4: n+2, 5: n+1}[n % 6]
    sieve = [True] * (n/3)
    sieve[0] = False
    for i in range(int(n**0.5)/3+1):
        if sieve[i]:
            k = 3*i+1 | 1
            sieve[((k*k)/3)::2*k] = [False]*((n/6-(k*k)/6-1)/k+1)
            sieve[(k*k+4*k-2*k*(i & 1))/3::2*k] = [False] * \
                ((n/6-(k*k+4*k-2*k*(i & 1))/6-1)/k+1)
    return [2, 3] + [3*i+1 | 1 for i in range(1, n/3-correction) if sieve[i]]


def generate_keypair(keySize=10):
    
    p = generateLargePrime(keySize)
    print(p)
    q = generateLargePrime(keySize)
    print(q)
    while(p == q):
        p = generateLargePrime(keySize)
        print(p)
        q = generateLargePrime(keySize)
        print(q)

    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = secure_rng.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)

    while g != 1:
        e = secure_rng.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key, n) for char in plaintext]
    # Return the array of bytes
    return cipher


def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    # Return the array of bytes as a string
    return "".join(plain)

"""
GUI CODE --- IRRELEVANT TO DEMO
"""
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.title = 'RSA Message Encyption & Decryption demo app'
        self.left = 0
        self.top = 0
        self.width = 720
        self.height = 480
        self.initUI()
 
    def initUI(self):
        self.setWindowTitle(self.title)

        self.setGeometry(self.left, self.top, self.width, self.height)
 
        self.createGridLayout()
 
        self.windowLayout = QVBoxLayout()
        self.windowLayout.addWidget(self.horizontalGroupBox)
        self.setLayout(self.windowLayout)

        self.show()

    def createGridLayout(self):
        self.horizontalGroupBox = QGroupBox()
        self.layout = QGridLayout()
        
        """
        Add UI elements below
        """
        # Create a separate layout to group the private/public key UI elements
        self.keyLayout = QGridLayout()

        # Add the public key display field
        publicKeyLabel = QLabel("Public Key: ")
        publicKeyField = QLineEdit(self)
        self.keyLayout.addWidget(publicKeyLabel, 0, 0)
        self.keyLayout.addWidget(publicKeyField, 0, 1)

        # Add the private key display field
        privateKeyLabel = QLabel("Private Key: ")
        privateKeyField = QLineEdit(self)
        self.keyLayout.addWidget(privateKeyLabel, 0, 2)
        self.keyLayout.addWidget(privateKeyField, 0, 3)

        # Add the generate key button
        generateKeysButton = QPushButton('Generate Keys', self)
        generateKeysButton.clicked.connect(self.generate_keypair_ev)
        generateKeysButton.setToolTip('Generates a Public/Private RSA Keypair')
        self.keyLayout.addWidget(generateKeysButton, 0, 4)

        # Add the input text field
        self.messageInputField = QPlainTextEdit(self)
        self.messageInputField.insertPlainText("Write message to encrypt/decrypt here....")

        # Add the output text field
        self.messageOutputField = QPlainTextEdit(self)
        self.messageOutputField.setReadOnly(True)

        # Add encrypt button
        encryptButton = QPushButton('Encrypt', self)
        encryptButton.clicked.connect(self.encrypt_ev)
        encryptButton.setToolTip('Encrypts a message using the RSA algorithm')

        # Add decrypt button
        decryptButton = QPushButton('Decrypt', self)
        decryptButton.clicked.connect(self.decrypt_ev)
        decryptButton.setToolTip('Decrypts a message encrypted by the RSA algorithm')

        # Add everything to the grid layout (so the items display)
        self.layout.addLayout(self.keyLayout, 0, 0)
        self.layout.addWidget(self.messageInputField, 1, 0) 
        self.layout.addWidget(encryptButton, 1, 1)
        self.layout.addWidget(self.messageOutputField, 2, 0)
        self.layout.addWidget(decryptButton, 2, 1)
 
        self.horizontalGroupBox.setLayout(self.layout)

    @pyqtSlot()
    def encrypt_ev(self):
        # TODO: Make this work regarless of whether we have previously encrypted a message.
        self.encrypted_msg = encrypt(self.privateKey, self.messageInputField.toPlainText())
        self.messageOutputField.setPlainText("".join(map(lambda x: str(x), self.encrypted_msg)))

    @pyqtSlot()
    def decrypt_ev(self):
        decrypted_msg = decrypt(self.publicKey, self.encrypted_msg)
        self.messageOutputField.setPlainText(str(decrypted_msg))

    @pyqtSlot()
    def generate_keypair_ev(self):
        print("Generating your public/private keypairs now . . .")
        self.publicKey, self.privateKey = generate_keypair()
        
        # Index 1 should be the public key text field
        self.keyLayout.itemAt(1).widget().setText(str(self.publicKey))
        # Index 3 should be the private key text field
        self.keyLayout.itemAt(3).widget().setText(str(self.privateKey))
 
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
