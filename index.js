const ffi = require("ffi");
const path = require("path");
const ref = require("ref");
const ArrayType = require("ref-array");
const ByteArray = ArrayType(ref.types.uint8);
const StructType = require("ref-struct");

const ArrayStruct = StructType({
  data: ByteArray,
  len: ref.types.int
});

const ArrayStructPtr = ref.refType(ArrayStruct);

//const CallbackFilter = ffi.Function("bool", ["int"]);

const lib = ffi.Library(
  path.join(__dirname, "./target/release/libffi_crypto"),
  {
    encrypt: [ArrayStructPtr, [ByteArray, "int"]]
  }
);

const array = [...Buffer.from(process.argv.slice(2).join(" "), "ascii")];

/* What if the returning array length is changed. It would be great to have the new length returned as well */
(function(js_array) {
  const ret_struct = lib.encrypt(js_array, js_array.length);
  const struct_value = ret_struct.deref();
  const arr_len = struct_value.len;

  const out = struct_value.data.buffer.reinterpret(arr_len).toString("base64");
  //console.log("Array bytes: ", out);
  //console.log("Array len: ", arr_len);
  console.log(out);
})(array);
