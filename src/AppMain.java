
public class AppMain {

	public static void main(String[] args) throws Exception {
		String[] generarClavesPeregrino = { "clavePeregrino" };
		GenerarClaves.main(generarClavesPeregrino);
//		String[] generarClavesOficina = { "claveOficina" };
//		GenerarClaves.main(generarClavesOficina);
//		String[] generarClavesAlbergue = { "claveAlbergue" };
//		GenerarClaves.main(generarClavesAlbergue);
		
		String[] generarCredencial = {"datos_peregrino.txt", "CPVPack", "clavePeregrino.privada"};
		GenerarCredencial.main(generarCredencial);
		
		String[] desempaquetarCredencial = {"CPVPack", "0", "clavePeregrino.publica"};
		DesempaquetarCredencial.main(desempaquetarCredencial);

	}

}
