
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerarCredencial {

	public static void main(String[] args) throws Exception {

		if (args.length != 4) {
			System.out.println("Generador de credencial");
			System.out.println("\tSintaxis:   java GenerarCredencial <fichero datos> <nombre paquete> "
					+ "<fichero clave publica oficina> <fichero clave privada peregrino");
			System.out.println("\tEjemplo: java GenerarCredencial datos_peregrino.txt CPVPack "
					+ "claveOficina.publica clavePeregrino.privada");
// java GenerarCredencial datos_peregrino.txt CPVPack claveOficina.publica clavePeregrino.privada
			System.exit(1);
		}

		String[] nombresCampo = { "nombre", "dni", "domicilio", "fechaCreacion", "lugarCreacion", "motivacionPeregrinaje" };
		String[] nombresBloque = { "datosPeregrino", "claveCifrada", "firma" };
		String datosJsonOrigen = Seguridad.castToJsonString(nombresCampo, args[0]);
		byte[] resumen = Seguridad.hash(datosJsonOrigen);
		List<byte[]> contenido = new ArrayList<>();
		Paquete paquete = new Paquete();

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);

		SecretKey clave = generadorDES.generateKey();
		PublicKey clavePublicaOficina = Seguridad.getPublicKey(args[2]);
		PrivateKey clavePrivadaPeregrino = Seguridad.getPrivateKey(args[3]);

		contenido.add(Seguridad.encriptarDES(datosJsonOrigen.getBytes(), clave));
		contenido.add(Seguridad.encriptarRSA(clave.getEncoded(), clavePublicaOficina));
		contenido.add(Seguridad.generarFirma(resumen, clavePrivadaPeregrino));

		Seguridad.empaquetar(paquete, args[1], nombresBloque, contenido);
		System.out.println("CREDENCIAL GENERADA EN " + args[1]);

	}

}