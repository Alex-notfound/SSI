
public class AppMain {

	public static void main(String[] args) throws Exception {

		String[] generarClavesPeregrino = { "clavePeregrino" };
		GenerarClaves.main(generarClavesPeregrino);
		String[] generarClavesOficina = { "claveOficina" };
		GenerarClaves.main(generarClavesOficina);
		String[] generarClavesAlbergue = { "claveAlbergue" };
		GenerarClaves.main(generarClavesAlbergue);

// java GenerarCredencial datos_peregrino.txt CPVPack claveOficina.publica clavePeregrino.privada
		String[] generarCredencial = { "datos_peregrino.txt", "CPVPack", "claveOficina.publica", "clavePeregrino.privada" };
		GenerarCredencial.main(generarCredencial);

// java DesempaquetarCredencial CPVPack 0 claveOficina.privada clavePeregrino.publica
		String[] desempaquetarCredencial = { "CPVPack", "0", "claveOficina.privada", "clavePeregrino.publica" };
		DesempaquetarCredencial.main(desempaquetarCredencial);

	}

}
