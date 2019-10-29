
import java.io.File;
import java.security.PrivateKey;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerarCredencial {

	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {

		if (args.length != 3) {
			System.out.println("Generador de credencial");
			System.out.println(
					"\tSintaxis:   java GenerarCredencial <fichero datos> <nombre paquete> <ficheros con las claves necesarias>");
			System.exit(1);
		}

		Scanner reader = new Scanner(new File(args[0]));
		String[] nombreCampos = { "nombre", "dni", "domicilio", "fechaCreacion", "lugarCreacion",
				"motivacionPeregrinaje" };
		Map<String, String> datos = new LinkedHashMap<>();
		int i = 0;
		while (reader.hasNextLine()) {
			datos.put(nombreCampos[i++], reader.nextLine());
		}
		String datosJsonOrigen = JSONUtils.map2json(datos);

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();
		PrivateKey clavePrivada = Seguridad.getPrivateKey(new File(args[2]));

		byte[] datosCifrados = Seguridad.encriptarDES(datosJsonOrigen.getBytes(), clave);

		byte[] claveCifrada = Seguridad.encriptarRSA(clave.getEncoded(), clavePrivada);

		byte[] resumen = Seguridad.hash(datosJsonOrigen);

		byte[] firma = Seguridad.generarFirma(resumen, clavePrivada);
		Paquete paquete = new Paquete();
		String[] nombresBloque = { "datosPeregrino", "claveCifrada", "firma" };
		paquete.anadirBloque(nombresBloque[0], datosCifrados);
		paquete.anadirBloque(nombresBloque[1], claveCifrada);
		paquete.anadirBloque(nombresBloque[2], firma);
		PaqueteDAO.escribirPaquete(args[1], paquete);
		System.out.println("CREDENCIAL GENERADA EN " + args[1]);

	}

}