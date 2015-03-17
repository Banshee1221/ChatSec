import pytest

# Functions
def add1(x):
	return x+1
def f():
	raise SystemExit(1);

# Tests
class TestScratch:
	def test_answer(self):
		assert add1(4) == 5
	def test_f(self):
		with pytest.raises(SystemExit):
			f()
	def test_str(self):
		x = 'this'
		assert 'h' in x
	def test_needsfiles(self, tmpdir):
		print tmpdir
		assert 1
