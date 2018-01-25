var $J = $J || function (obj) {

	var priv = {};
	var pub = {};

	var JavaArray = null;
	var JavaClass = null;
	Java.performNow(function () {
		JavaArray = Java.use("java.lang.reflect.Array");
		JavaClass = Java.use("java.lang.Class");
	});

	function isNativeType(klass) {
		return ['int', 'long', 'boolean', 'double', 'byte', 'char'].indexOf(klass) != -1;
	}
	
	pub.init = function (obj) {
		priv.obj = obj;
	};

	pub.getField = function (fieldName) {
		return priv.obj.class.getDeclaredField(fieldName);
	};

	pub.isStaticField = function (fieldName) {
		return (this.getField(fieldName).getModifiers() & 8) != 0; 
	};

	pub.getFieldValue = function (fieldName) {
		var field = pub.getField(fieldName);
		var obj = pub.isStaticField(fieldName) ? null : priv.obj;
		field.setAccessible(true);

		var klass = field.getType().toString().split(' ').pop();
		switch (klass) {
			case "int":
				return field.getInt(obj);
			case "boolean":
				return field.getBoolean(obj);
			case "long":
				return field.getLong(obj);
			case "double":
				return field.getDouble(obj);
			case "byte":
				return field.getByte(obj);
			case "char":
				return field.getChar(obj);
			default:
				return $J(field.get(obj)).cast(klass);
		}
	};

	pub.asList = function () {
		var len = JavaArray.getLength(priv.obj);
		var ret = [];
		for (var i = 0 ; i < len ; ++i) {
			ret.push(JavaArray.get(priv.obj, i));
		}
		return ret;
	};

	pub.setFieldValue = function (fieldName, fieldValue) {
		var field = pub.getField(fieldName);
		var obj = pub.isStaticField(fieldName) ? null : priv.obj;
		field.setAccessible(true);
		var klass = field.getType().toString().split(' ').pop();
		switch (klass) {
			case "int":
				field.setInt(obj, fieldValue);
				break;
			case "boolean":
				field.setBoolean(obj, fieldValue);
				break;
			case "long":
				field.setLong(obj, fieldValue);
				break;
			case "double":
				field.setDouble(obj, fieldValue);
				break;
			case "byte":
				field.setByte(obj, fieldValue);
				break;
			case "char":
				field.setChar(obj, fieldValue);
				break;
			default:
				field.set(obj, fieldValue);
		}

		return $J(priv.obj);
	};

	pub.at = function (index) {
		return $J(JavaArray.get(priv.obj, index));
	};

	pub.cast = function (klass) {
		if (priv.obj) {
			if (typeof(klass) == 'string') {
				Java.performNow(function () {
					klass = Java.use(klass);
				});
				return pub.cast(klass);
			} else {
				return $J(Java.cast(priv.obj, klass));
			}
		} else {
			return null;
		}
	};

	pub.getObject = function () {
		return priv.obj;
	};

	pub.toString = function (options) {

		function friendlierName(name) {
			var s = name.split(' ');
			var lastComponent = s.pop().split('.').pop();
			s.push(lastComponent);
			return s.join(' ');
		}

		var s = 'class ' + priv.obj.class.getName() + ' {\n\t// Fields\n';
		var fields = priv.obj.class.getDeclaredFields();
		for (var i in fields) {
			var field = fields[i];

			if (options && options.evaluateFields) {
				var fieldValue = pub.getFieldValue(field.getName());
				fieldValue = fieldValue.getObject ? fieldValue.getObject() : fieldValue;
				s += '\t' + friendlierName(field.toString()) + '; // = ' + fieldValue + ';\n';
			} else {
				s += '\t' + friendlierName(field.toString()) + ';\n';
			}
		}
		if (options && options.printMethods) {
			s += '\n\n\t // Methods\n';
			var methods = priv.obj.class.getDeclaredMethods();
			for (var i in methods) {
				var field = methods[i];
				s += '\t' + friendlierName(field.toString()) + ';\n'
			}
		}
		s += '}\n';

		return s;
	};

	pub.init(obj);

	return pub;
};


module.exports = $J;