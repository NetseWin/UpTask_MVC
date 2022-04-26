<?php

	namespace Controllers;

use Classes\Email;
use Model\Usuario;
use MVC\Router;

	class LoginController {

		public static function login(Router $router){
			
			$alertas = [];
			
			if($_SERVER['REQUEST_METHOD'] === 'POST'){

				$usuario = new Usuario($_POST);
				$alertas = $usuario->validarLogin();

				if(empty($alertas)){
					//Verificar que el usuario exista
					$usuario = Usuario::where('email', $usuario->email);

					if(!$usuario || !$usuario->confirmado ){
						//si el usuario no existe
						Usuario::setAlerta('error', 'El usuario no existe o no esta confirmado');
					}else {
						//El usuario Existe y debemos comprobar su password
						if(password_verify($_POST['password'], $usuario->password)){
							//Password coinciden y arrancamos session
							// Iniciar la sesión
							session_start();    
							$_SESSION['id'] = $usuario->id;
							$_SESSION['nombre'] = $usuario->nombre;
							$_SESSION['email'] = $usuario->email;
							$_SESSION['login'] = true;
							//Redireccionar
							header('Location: /dashboard');

						}else {
							//Password no coinciden
							Usuario::setAlerta('error', 'Password incorrecto');
						}
					}

				}
			}
			$alertas = Usuario::getAlertas();
			//Render a la vista
			$router->render('auth/login', [
				'titulo' => 'Iniciar Sesion',
				'alertas' => $alertas
			]);
		}

		public static function logout(){
			//iniciar session toma toda la informacion de la session que esta en el servidor
			session_start();
			$_SESSION = [];
			header('Location: /');
		
		}

		public static function crear(Router $router){

			$usuario = new Usuario();
			$alertas = [];
			
			if($_SERVER['REQUEST_METHOD'] === 'POST'){

				$usuario->sincronizar($_POST);
				$alertas = $usuario->validarNuevaCuenta();

				//Una vez validada la cuenta verificamos que no haya alertas para realizar las
				//siguientes
				if(empty($alertas)){

					$existeUsuario = Usuario::where('email', $usuario->email);

					if($existeUsuario){
						Usuario::setAlerta('error', 'El usuario ya esta registrado');
						$alertas = Usuario::getAlertas();
					}else {
						//Crear un nuevo usuario
						//1-hashear el password
						$usuario->hashPassword();

						//2-eliminar password2 para ActiveRecord
						unset($usuario->password2);

						//3-generar token
						$usuario->crearToken();

						$resultado = $usuario->guardar();

						//Enviar email
						$email = new Email($usuario->mail, $usuario->nombre, $usuario->token);
						$email->enviarConfirmacion();

						if($resultado){
							
							header('Location: /mensaje');
						}

					}

				}
				
			}

			//Render a la vista
			$router->render('auth/crear', [
				'titulo' => 'Crea tu cuenta en UpTask',
				'usuario' => $usuario,
				'alertas' => $alertas
			]);
		}

		public static function olvide(Router $router){
			$alertas = [];
			if($_SERVER['REQUEST_METHOD'] === 'POST'){
				$usuario = new Usuario($_POST);
				$alertas = $usuario->validarEmail();

				//Si no hay alertas de errores
				if(empty($alertas)){
					//Buscar el usuario
					$usuario = Usuario::where('email', $usuario->email);
					//doble comprobacion, se supone que a esta altura estamos reestableciento 
					//la contrasenha y se supone que el usuario debe estar confirmado
					if($usuario && $usuario->confirmado){
						//Encontre al usuario, y tambien esta confirmado
						//Generar un nuevo token
						 $usuario->crearToken();
						 unset($usuario->password2);

						 //Actualizar el usuario
						 $usuario->guardar();

						 //Enviar el email
						$email = new Email($usuario->email, $usuario->nombre, $usuario->token);
						$email->enviarInstrucciones();

						 //Imprimir la alerta
						 Usuario::setAlerta('exito','Hemos enviado las instrucciones a tu email');

					}else {
						//No existe el usuario
						Usuario::setAlerta('error', 'El usuario no existe o no esta confirmado');
					}
					
				}
			}
			$alertas = Usuario::getAlertas();
			//Render a la vista
			$router->render('auth/olvide', [
				'titulo' => 'Olvide mi Password',
				'alertas' => $alertas
			]);
		}

		public static function reestablecer(Router $router){
			$mostrar = true;
			$alertas = [];
			$token = $_GET['token'];
			//si intentan ingresar a reestablecer sin token los enviamos al login
			if(!$token) header('Location: /');

			//Identificar al usuario del token
			$usuario = Usuario::where('token', $token);

			if(!$usuario){
				//El usuario No Existe en la base de datos s/ token
				Usuario::setAlerta('error', 'Token No Valido');
				$mostrar = false;
			}
				
			if($_SERVER['REQUEST_METHOD'] === 'POST'){
				
				//Anhadir el nuevo password
				$usuario->sincronizar($_POST);

				//validar el password ingresado
				$alertas = $usuario->validarPassword();

				//si el array de alerta se encuentra vacia, quiere decir que pasamos la validacion
				if(empty($alertas)){
					//Hashear el nuevo password
					$usuario->hashPassword();
					
					//Eliminar el token
					$usuario->token = '';

					//Guardar el usuario en la base de datos
					$resultado = $usuario->guardar();

					//Redireccionar al login para su ingreso
					if($resultado){
						header('Location: /');
					}
				}
			}
			$alertas = Usuario::getAlertas();
			//Render a la vista
			$router->render('auth/reestablecer', [
				'titulo' => 'Reestablecer Password',
				'alertas' => $alertas,
				'mostrar' => $mostrar
			]);
		}

		public static function mensaje(Router $router){
			
			//Render a la vista
			$router->render('auth/mensaje', [
				'titulo' => 'Cuenta creada exitosamente'
			]);
		
		}

		public static function confirmar(Router $router){

			$token = $_GET['token'];

			//Si alguien intenta adivinar el token lo mandamos al login
			if(!$token){
				header('Location: /');
			}

			//Encontar al usuario con el token obtenido
			$usuario = Usuario::where('token', $token);
			
			if(empty($usuario)){
				//No se encontro ningun usuario con ese token
				Usuario::setAlerta('error', 'Token No Valido');
			}else {
				//Confirmar la cuenta
				$usuario->confirmado = 1;
				$usuario->token = '';
				unset($usuario->password2);
				
				$usuario->guardar();
				Usuario::setAlerta('exito', 'Cuenta Comprobada Correctamente');
			}

			$alertas = Usuario::getAlertas();
			$router->render('auth/confirmar', [
				'titulo' => 'Confirme tu cuenta UpTask',
				'alertas' => $alertas
			]);
		
		}
		
	}