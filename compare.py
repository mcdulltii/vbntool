import sys

def main(kwargs):
    f1, f2 = open(kwargs[0]).read(), open(kwargs[1]).read()
    index = 0
    offset = 0
    while index < min(len(f1), len(f2)):
        if f1[index+offset] != f2[index]:
            break
        index += 1
    if index == min(len(f1), len(f2)):
        print 'Files are the same'
    else:
        print 'Difference from index {}'.format(index)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'Usage: python compare.py <file1> <file2>'
        sys.exit()
    main(sys.argv[1:])
