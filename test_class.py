
class TestClass:

    def __init__(self, name):
        self.name = name

    def change_name(self):
        self.name = 'frank'
        print(self.name)


tc = TestClass('jim')
print(tc.name)

tc.change_name()
print(tc.name)
