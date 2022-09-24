const BN = require('bn.js');

class BufferCursor {
  constructor(buffer) {
    this._buffer = buffer;
    this._position = 0;
  }

  writeUInt32LE(val) {
    this._writeStandard(this.writeUInt32LE.name, val, 4);
  }

  writeInt32LE(val) {
    this._writeStandard(this.writeInt32LE.name, val, 4);
  }

  writeUInt64LE(value) {
    if (!(value instanceof BN)) value = new BN(value);
    this.writeBytes(value.toBuffer('le', 8));
  }

  writeBytes(buffer) {
    if (!buffer || !buffer.length) return;
    if (this._position + buffer.length > this._buffer.length)
      throw new RangeError('Index out of range');
    buffer.copy(this._buffer, this._position);
    this._position += buffer.length;
  }

  _writeStandard(fn, val, len) {
    this._buffer[fn](val, this._position);
    this._position += len;
  }
}

module.exports = BufferCursor;
