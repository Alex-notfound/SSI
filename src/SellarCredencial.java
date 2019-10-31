import java.security.MessageDigest;
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
		if (args.length != 5) {
			System.out.println("Sellador de credencial");
			System.out.println("\tSintaxis:   java SellarCredencial <fichero paquete> <identificador de albergue> \n"
					+ "<fichero clave privada albergue> <fichero clave publica peregrino>");
			System.out.println("java SellarCredencial CPVPack albergue1 claveAlbergue.privada claveOficina.publica");
// java SellarCredencial file CPVPack albergue1 claveAlbergue.privada claveOficina.publica
			System.exit(1);
		}

		String[] nombreCampos = { "nombre", "fechaCreacion", "lugarCreacion", "incidencias" };
		String[] nombresBloque = { args[2] + "_datos", args[2] + "_clave", args[2] + "_firma" };
		String datosJsonOrigen = Seguridad.castToJsonString(nombreCampos, args[0]);
		List<byte[]> contenido = new ArrayList<>();
		Paquete paquete = PaqueteDAO.leerPaquete(args[1]);
		byte[] resumen = Seguridad.hash(datosJsonOrigen, paquete.getContenidoBloque("firma"));

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits

		SecretKey clave = generadorDES.generateKey();
		PrivateKey clavePrivadaAlbergue = Seguridad.getPrivateKey(args[args.length - 2]);
		PublicKey clavePublicaOficina = Seguridad.getPublicKey(args[args.length - 1]);

		contenido.add(Seguridad.encriptarDES(datosJsonOrigen.getBytes(), clave));
		contenido.add(Seguridad.encriptarRSA(clave.getEncoded(), clavePublicaOficina));
		contenido.add(Seguridad.generarFirma(resumen, clavePrivadaAlbergue));

		Seguridad.empaquetar(paquete, args[1], nombresBloque, contenido);
		System.out.println("CREDENCIAL SELLADA EN " + args[2]);
	}

}
