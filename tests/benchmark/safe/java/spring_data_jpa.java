// BENCHMARK: safe - spring_data_jpa_named_params
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // Safe: Spring Data JPA named parameters prevent SQL injection
    @Query("SELECT u FROM User u WHERE u.username = :username AND u.active = true")
    List<User> findByUsername(@Param("username") String username);
}
