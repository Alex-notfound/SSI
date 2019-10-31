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

		Security.addProvider(new BouncyCastleProvider());
		PrivateKey clavePrivadaOficina = Seguridad.getPrivateKey(args[args.length - 2]);
		PublicKey clavePublicaPeregrino = Seguridad.getPublicKey(args[args.length - 1]);

		byte[] claveDescifrada = Seguridad.desencriptarRSA(paquete.getContenidoBloque("clave"), clavePrivadaOficina);
		SecretKey clave = new SecretKeySpec(claveDescifrada, "DES");
		byte[] datosDescifrados = Seguridad.desencriptarDES(paquete.getContenidoBloque("datos"), clave);
		byte[] resumen = Seguridad.hash(new String(datosDescifrados, "UTF-8"));

		if (Seguridad.validarFirma(resumen, clavePublicaPeregrino, paquete.getContenidoBloque("firma"))) {
			System.out.println("Los datos del peregrino son correctos: ");
			Seguridad.mostrarBytes(datosDescifrados);

			PublicKey clavePublicaAlbergue;
			for (int i = 2; i <= Integer.parseInt(args[1]) * 2; i += 2) {

				clavePublicaAlbergue = Seguridad.getPublicKey(args[i + 1]);
				claveDescifrada = Seguridad.desencriptarRSA(paquete.getContenidoBloque(args[i] + "_clave"), clavePrivadaOficina);
				clave = new SecretKeySpec(claveDescifrada, "DES");
				datosDescifrados = Seguridad.desencriptarDES(paquete.getContenidoBloque(args[i] + "_datos"), clave);
				resumen = Seguridad.hash(new String(datosDescifrados, "UTF-8"), paquete.getContenidoBloque("firma"));
				if (Seguridad.validarFirma(resumen, clavePublicaAlbergue, paquete.getContenidoBloque(args[i] + "_firma"))) {
					System.out.println("\nSello de " + args[i] + " válido: ");
					Seguridad.mostrarBytes(datosDescifrados);
				} else {
					System.out.println("\nSello de " + args[i] + " NO VÁLIDO");
				}
			}
		} else {
			System.out.println("LOS DATOS HAN SIDO MANIPULADOS");
		}

	}

}