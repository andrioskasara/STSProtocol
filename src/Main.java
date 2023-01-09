public class Main {
    public static void main(String[] args) {
        User Alice = new User("Alice");
        User Bob = new User("Bob");
        try {
            Alice.sendFirstMessage(Bob);
        }
        catch(Exception e){
            System.err.println(e.getMessage());
        }
    }
}