import java.io.File;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarCredencial {

	public static void main(String[] args) throws Exception {
		if (args.length < 2 || args.length < 2 + Integer.parseInt(args[1]) * 3) {
			System.out.println("Desempaquetador de credencial");
			System.out.println("\tSintaxis:   java SellarCredencial <fichero paquete> <identificador de albergue> \n"
					+ "<ficheros con las claves necesarias> ");
			System.exit(1);
		}

		String[] nombreCampos = { "nombre", "fechaCreacion", "lugarCreacion", "incidencias" };
		String datosJsonOrigen = Seguridad.castToJsonString(nombreCampos, args[0]);
		String[] nombresBloque = { args[1] + "datosCifrados", args[1] + "claveCifrada", args[1] + "firma" };
		Paquete paquete = PaqueteDAO.leerPaquete(args[1]);
		List<byte[]> contenido = new ArrayList<>();
		byte[] resumen = Seguridad.hash(datosJsonOrigen);

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits

		SecretKey clave = generadorDES.generateKey();
		PrivateKey clavePrivada = Seguridad.getPrivateKey(new File(args[args.length - 1]));

		contenido.add(Seguridad.encriptarDES(datosJsonOrigen.getBytes(), clave));
		contenido.add(Seguridad.encriptarRSA(clave.getEncoded(), clavePrivada));
		contenido.add(Seguridad.generarFirma(resumen, clavePrivada));

		Seguridad.empaquetar(paquete, args[0], nombresBloque, contenido);
		System.out.println("CREDENCIAL SELLADA EN " + args[1]);
	}

}
