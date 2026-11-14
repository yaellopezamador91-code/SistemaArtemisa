# Sistema ARTEMISA Muay Thai

## Requisitos
- Windows 10 u 11 y Python 3.10 o posterior.
- No necesita instalar paquetes de Python.
- Para códigos QR, lector USB que funcione como teclado.

## Ejecutar desde VS Code
1. Abre esta carpeta en VS Code.
2. En Terminal > Nuevo terminal, ejecuta `py -3 app.py`.
3. Abre http://127.0.0.1:8000 en el navegador.
4. La primera vez, crea la cuenta administradora con una contraseña de al menos 12 caracteres.
5. El administrador crea cada cuenta de recepción y define su contraseña inicial. La recepcionista entra siempre con ese nombre y contraseña; no necesita un código nuevo en cada inicio. Desde la lista de cuentas, el administrador puede cambiar el nombre, establecer una contraseña nueva o desactivar/reactivar el acceso.

Deja abierta la terminal mientras uses el sistema. Para detenerlo, presiona Ctrl+C. Después de actualizar la aplicación, detén el servidor y vuelve a iniciarlo para cargar los cambios y aplicar las migraciones de la base.

## Funciones
- Panel adaptable a teléfono y computadora. Recepción ve las secciones de Asistencia, Alumnos y Cobros. La sección Administrador reúne las cuentas de recepción, tarifas, reportes semanales y asistencias/actividad.
- Sesión recordada durante 30 días y persistida en la base de datos, incluso si el servidor se reinicia.
- Alta y edición de alumnos con nombre, fecha de nacimiento, edad calculada, celular, contacto de emergencia, horario editable, fecha límite y modalidad de pago.
- Al registrar un alumno se abre su QR. Puede imprimirse o descargarse como SVG para compartirlo. El QR no caduca automáticamente; permanece asociado al alumno y el acceso se valida con su estado y vigencia al escanearlo. El logotipo incluido en `static/logo.png` aparece en el encabezado, la credencial y la pestaña del navegador.
- Cada alumno tiene una credencial imprimible con espacio para fotografía infantil de 2.5 × 3 cm, nombre, horario, QR y contacto del tutor. El tutor usa el mismo nombre y teléfono capturados como contacto de emergencia; no se solicitan dos veces.
- Alertas de pago, tolerancia de cuatro días y registro de intentos de acceso denegados.
- Perfiles de administración y recepción. Ambos pueden editar datos de contacto, modalidad de pago y estado, incluida la baja.
- Solo el administrador puede marcar una beca y establecer su porcentaje. En Cobros, la mensualidad muestra automáticamente el porcentaje y total con descuento antes de guardar; también queda reflejado en el recibo.
- Tarifas sugeridas editables por el administrador. La clase personalizada inicia en $300 MXN. El monto de cada cobro puede ajustarse al momento de registrarlo.
- Cobros asociados a la cuenta que los registró, folio y recibo imprimible.
- Los pagos por clase individual o fin de semana generan un pase de una entrada.
- Resumen diario, historial de actividad y reportes Excel semanales, mensuales o completos. Cada archivo tiene pestañas separadas de asistencias y pagos.
- Datos guardados en `atemisa.db` y conservados en las operaciones normales del sistema.

## Datos existentes
La actualización conserva las cuentas, alumnos, pagos y asistencias ya registrados. Al iniciar la versión nueva, se agregan las columnas necesarias en la base SQLite existente. Las cuentas de sesión anteriores no se migran: inicia sesión una vez después de actualizar; desde entonces la sesión se conserva hasta 30 días.

## Acceso remoto
Esta versión escucha solo en la computadora local en 127.0.0.1. No la expongas directamente a Internet. Para el acceso remoto hace falta configurar alojamiento, HTTPS y almacenamiento persistente.
