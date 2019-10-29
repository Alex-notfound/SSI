
import java.io.File;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerarCredencial {

	public static void main(String[] args) throws Exception {

		if (args.length != 3) {
			System.out.println("Generador de credencial");
			System.out.println(
					"\tSintaxis:   java GenerarCredencial <fichero datos> <nombre paquete> <ficheros con las claves necesarias>");
			System.exit(1);
		}

		String[] nombresCampo = { "nombre", "dni", "domicilio", "fechaCreacion", "lugarCreacion",
				"motivacionPeregrinaje" };
		String[] nombresBloque = { "datosPeregrino", "claveCifrada", "firma" };
		String datosJsonOrigen = Seguridad.castToJsonString(nombresCampo, args[0]);
		byte[] resumen = Seguridad.hash(datosJsonOrigen);
		List<byte[]> contenido = new ArrayList<>();
		Paquete paquete = new Paquete();

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits

		SecretKey clave = generadorDES.generateKey();
		PrivateKey clavePrivada = Seguridad.getPrivateKey(new File(args[2]));

		contenido.add(Seguridad.encriptarDES(datosJsonOrigen.getBytes(), clave));
		contenido.add(Seguridad.encriptarRSA(clave.getEncoded(), clavePrivada));
		contenido.add(Seguridad.generarFirma(resumen, clavePrivada));

		Seguridad.empaquetar(paquete, args[1], nombresBloque, contenido);
		System.out.println("CREDENCIAL GENERADA EN " + args[1]);

	}

}