<?php

namespace Model;

class Usuario extends ActiveRecord {

	protected static $tabla = 'usuarios';
	protected static $columnasDB = ['id', 'nombre', 'email', 'password', 'token', 'confirmado'];

	public $id;
	public $nombre;
	public $email;
	public $password;
	public $password2;
	public $token;
	public $confirmado;

	public function __construct($args = [])
	{
		$this->id = $args['id'] ?? null;
		$this->nombre = $args['nombre'] ?? '';
		$this->email = $args['email'] ?? '';
		$this->password = $args['password'] ?? '';
		$this->password2 = $args['password2'] ?? '';
		$this->token = $args['token'] ?? '';
		$this->confirmado = $args['confirmado'] ?? 0;
	}
	//Metodo que valida informacion del login
	public function validarLogin(){

		if(!$this->email){
			self::$alertas['error'][] = 'El Email del Usuario es Obligatorio';
		}
		if( !filter_var($this->email, FILTER_VALIDATE_EMAIL) ){
			self::$alertas['error'][] = 'El Email no es valido';
		}
		if(!$this->password){
			self::$alertas['error'][] = 'El Password no puede ir vacio';
		}
		return self::$alertas;
	}

	//Validacion para cuentas nuevas
	public function validarNuevaCuenta(){
		if(!$this->nombre){
			self::$alertas['error'][] = 'El Nombre del Usuario es Obligatorio';
		}
		if(!$this->email){
			self::$alertas['error'][] = 'El Email del Usuario es Obligatorio';
		}
		if(!$this->password){
			self::$alertas['error'][] = 'El Password no puede ir vacio';
		}
		if(strlen($this->password) <  6){
			self::$alertas['error'][] = 'El Password debe contener al menos 6 caracteres';
		}
		if($this->password !== $this->password2){
			self::$alertas['error'][] = 'Los Passwords son diferentes';
		}
		return self::$alertas;
	}
	//metodo que hashea password
	public function hashPassword(){
		$this->password = password_hash($this->password, PASSWORD_BCRYPT);
	}
	//metodo generador de token
	public function crearToken(){
		$this->token = uniqid();
	}
	//validar un email
	public function validarEmail(){
		if(!$this->email){
			self::$alertas['error'][] = 'El Email es Obligatorio';
		}
		if( !filter_var($this->email, FILTER_VALIDATE_EMAIL) ){
			self::$alertas['error'][] = 'El Email no es valido';
		}
		return self::$alertas;
	}
	//metodo que valida el password
	public function validarPassword(){
		if(!$this->password){
			self::$alertas['error'][] = 'El Password no puede ir vacio';
		}
		if(strlen($this->password) <  6){
			self::$alertas['error'][] = 'El Password debe contener al menos 6 caracteres';
		}
		
		return self::$alertas;
	}
}