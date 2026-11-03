package com.oauth.authorization.repo;

import com.oauth.authorization.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

}
