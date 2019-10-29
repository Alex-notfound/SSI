import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarCredencial {

	public static void main(String[] args) throws Exception {
		if (args.length < 2 || args.length < 2 + Integer.parseInt(args[1]) * 3) {
			System.out.println("Desempaquetador de credencial");
			System.out.println("\tSintaxis:   java DesempaquetarCredencial <fichero paquete> <num. albergues (N)> \r\n"
					+ "<identificador albergue 1> <ficheros claves albergue 1> \r\n" + "... \r\n"
					+ "<identificador albergue N> <ficheros claves albergue N> \r\n"
					+ "<ficheros con otras claves necesarias> ");
			System.exit(1);
		}

		// packCPV 0 clave.publica
		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		List<String> nombresBloque = paquete.getNombresBloque();
		System.out.println(nombresBloque.toString());

		Security.addProvider(new BouncyCastleProvider());
		PublicKey clavePublica = Seguridad.getPublicKey(new File(args[args.length - 1]));

		byte[] claveDescifrada = Seguridad.desencriptarRSA(paquete.getContenidoBloque(nombresBloque.get(0)),
				clavePublica);
		SecretKey clave = new SecretKeySpec(claveDescifrada, "DES");
		byte[] datosDescifrados = Seguridad.desencriptarDES(paquete.getContenidoBloque(nombresBloque.get(1)), clave);
		byte[] resumen = Seguridad.hash(new String(datosDescifrados, "UTF-8"));

		System.out.println(
				Seguridad.validarFirma(resumen, clavePublica, paquete.getContenidoBloque(nombresBloque.get(2))));

	}

}