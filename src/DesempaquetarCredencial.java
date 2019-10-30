import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarCredencial {

	public static void main(String[] args) throws Exception {
		if (args.length != 4 + Integer.parseInt(args[1]) * 2) {
			System.out.println("Desempaquetador de credencial");
			System.out.println("\tSintaxis:   java DesempaquetarCredencial <fichero paquete> <num. albergues (N)> \r\n"
					+ "<identificador albergue 1> <fichero clave publica albergue 1> \r\n" + "... \r\n"
					+ "<identificador albergue N> <fichero clave publica albergue N> \r\n"
					+ "<fichero clave privada oficina> <fichero clave publica peregrino> ");
			System.out.println("\tEjemplo: java DesempaquetarCredencial CPVPack 0 claveOficina.privada clavePeregrino.publica");
// java DesempaquetarCredencial CPVPack 0 claveOficina.privada clavePeregrino.publica
			System.exit(1);
		}

		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		List<String> nombresBloque = paquete.getNombresBloque();
		System.out.println(nombresBloque.toString());

		Security.addProvider(new BouncyCastleProvider());
		PublicKey clavePublicaPeregrino = Seguridad.getPublicKey(args[args.length - 1]);
		PrivateKey clavePrivadaOficina = Seguridad.getPrivateKey(args[args.length - 2]);

		byte[] claveDescifrada = Seguridad.desencriptarRSA(paquete.getContenidoBloque(nombresBloque.get(0)), clavePrivadaOficina);
		SecretKey clave = new SecretKeySpec(claveDescifrada, "DES");
		byte[] datosDescifrados = Seguridad.desencriptarDES(paquete.getContenidoBloque(nombresBloque.get(1)), clave);
		byte[] resumen = Seguridad.hash(new String(datosDescifrados, "UTF-8"));

		System.out.println(
				Seguridad.validarFirma(resumen, clavePublicaPeregrino, paquete.getContenidoBloque(nombresBloque.get(2))));

	}

}