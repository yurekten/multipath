import random

if __name__ == '__main__':
    x = '.'.join('%s' % random.randint(1, 254) for i in range(2))
    print(x)