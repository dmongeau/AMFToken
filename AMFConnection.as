


package {
	
	import com.adobe.crypto.MD5;
	import flash.net.*;
	import flash.system.System;
    import flash.utils.ByteArray;
    import flash.utils.getTimer;

	
	public class AMFConnection extends NetConnection {
		
		private var _encodingKey:String = '$djlk9mfl;_xKk';
		private var _reencodingKey:String;
		private var uuid:String;
		
		public function AMFConnection():void {
		
		}
		
		public function secureCall(command:String, param:Object, callback:Function, error:Function):void {
			
			
			var responder:Responder = new Responder(function(obj:Object) {
				_reencodingKey = obj.key.key;
				trace('newkey : '+_reencodingKey);
				trace('callback : '+obj.data);
				callback(obj.data);
			},function(obj) {
				trace('error : '+obj);
				error(obj);
			});
			
			var timestamp:Number = Math.round((new Date()).getTime()/1000);
			
			var resp:Object = new Object();
			resp.uuid = _getUUID();
			resp.signature = _getSignature(command,timestamp);
			resp.timestamp = timestamp
			resp.data = param;
			//if(_reencodingKey) resp.key = _reencodingKey;
			//else resp.key = _encodingKey;
			
			call(command,responder,resp);
			
		}
		
		protected function _getSignature(command:String, timestamp:Number) {
			
			if(_reencodingKey && _reencodingKey.length) {
				return MD5.hash(command+String(timestamp)+_reencodingKey);
			} else {
				return MD5.hash(command+String(timestamp)+_encodingKey);
			}
			
		}
		
		protected function _getUUID() {
			
			if(!uuid) {
				
				var charCodes:Array = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70];
				
				var r:uint = uint(new Date().time);
				//trace(r);
				var buff:ByteArray = new ByteArray();
				//trace(System.totalMemory ^ r);
				buff.writeUnsignedInt(System.totalMemory ^ r);
				buff.writeInt(getTimer() ^ r);
				buff.writeDouble(Math.random() * r);
				
				buff.position = 0;
				var chars:Array = new Array(36);
				var index:uint = 0;
				for (var i:uint = 0; i < 16; i++)
				{
						if (i == 4 || i == 6 || i == 8 || i == 10)
						{
								chars[index++] = 45; // Hyphen char code
						}
						var b:int = buff.readByte();
						chars[index++] = charCodes[(b & 0xF0) >>> 4];
						chars[index++] = charCodes[(b & 0x0F)];
				}
				uuid = String.fromCharCode.apply(null, chars);
				
				trace(uuid);

			}
			return uuid;
			
		}
	
	}
	

}