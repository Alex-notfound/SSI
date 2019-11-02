import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarCredencial {

	public static void main(String[] args) throws Exception {
		if (args.length != 4) {
			System.out.println("Sellador de credencial");
			System.out.println("\tSintaxis:   java SellarCredencial <fichero paquete> <identificador de albergue> \n"
					+ "<fichero clave privada albergue> <fichero clave publica peregrino>");
			System.out.println("Ejemplo: java SellarCredencial CPVPack albergue1 claveAlbergue1.privada claveOficina.publica");
			System.exit(1);
		}

		String[] nombreCampos = { "nombre", "fecha de creacion", "lugar de creacion", "incidencias" };
		String[] nombresBloque = { args[1] + "_datos", args[1] + "_clave", args[1] + "_firma" };
		String datosJsonOrigen = Seguridad.castToJsonString(nombreCampos);
		List<byte[]> contenido = new ArrayList<>();
		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		byte[] resumen = Seguridad.hash(datosJsonOrigen, paquete.getContenidoBloque("firma"));

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits

		SecretKey clave = generadorDES.generateKey();
		PrivateKey clavePrivadaAlbergue = Seguridad.getPrivateKey(args[2]);
		PublicKey clavePublicaOficina = Seguridad.getPublicKey(args[3]);

		contenido.add(Seguridad.encriptarDES(datosJsonOrigen.getBytes(), clave));
		contenido.add(Seguridad.encriptarRSA(clave.getEncoded(), clavePublicaOficina));
		contenido.add(Seguridad.generarFirma(resumen, clavePrivadaAlbergue));

		Seguridad.empaquetar(paquete, args[0], nombresBloque, contenido);
		System.out.println("CREDENCIAL SELLADA EN " + args[0]);
	}

}
