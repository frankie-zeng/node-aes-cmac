var index = require('../index.js');
var assert = require('assert');

describe('index (module entry point)', function () {
  describe('tdesCmac(key, message, [options])', function () {
    it('performs the TDES-CMAC algorithm', function () {
      var key = Buffer.from('0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123', 'hex');
      var message = Buffer.from('', 'hex');
      var result = index.tdesCmac(key, message);
      assert.equal(result, '7db0d37df936c550');
    });
  });
  describe('aesCmac(key, message, [options])', function () {
    it('performs the AES-CMAC algorithm', function () {
      var key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
      var message = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
      var result = index.aesCmac(key, message);
      assert.equal(result, '070a16b46b4d4144f79bdd9dd04a287c');
    });

    it('can take a buffer or string as the key', function () {
      var stringKey = 'averysecretvalue';
      var bufferKey = Buffer.from(stringKey);
      var message = Buffer.from('some message');
      assert.equal(index.aesCmac(stringKey, message), index.aesCmac(bufferKey, message));
    });

    it('can take a buffer or string as the message', function () {
      var key = 'averysecretvalue';
      var stringMessage = 'some message';
      var bufferMessage = Buffer.from(stringMessage);
      assert.equal(index.aesCmac(key, stringMessage), index.aesCmac(key, bufferMessage));
    });

    it('returns a buffer as the response if options.returnAsBuffer == true', function () {
      var key = 'k3Men*p/2.3j4abB';
      var message = 'this|is|a|test|message';
      var options = {returnAsBuffer: true};
      var result = index.aesCmac(key, message, options);
      assert(result instanceof Buffer, 'Did not get a Buffer object.');
      assert.equal(result.toString('hex'), '0125c538f8be7c4eea370f992a4ffdcb');
    });

    it('throws an error if the key length is invalid', function () {
      assertAesCmacError('key', 'some message', 'Keys must be 128, 192, or 256 bits in length.');
    });

    it('throws an error if the key is neither Buffer nor string', function () {
      var expected = 'Keys must be provided as a Buffer or string.';
      assertAesCmacError(null, 'any message', expected);
      assertAesCmacError(123, 'any message', expected);
    });

    it('throws an error if the message is neither string nor Buffer', function () {
      var expected = 'The message must be provided as a string or Buffer.';
      assertAesCmacError('averysecretvalue', null, expected);
      assertAesCmacError('averysecretvalue', {}, expected);
    });

    function assertAesCmacError(key, message, expectedErrorMessage) {
      assert.throws(function () {
          index.aesCmac(key, message);
        },
        function (error) {
          assert.equal(error.message, expectedErrorMessage);
          return true;
        }
      );
    }
  });
});
