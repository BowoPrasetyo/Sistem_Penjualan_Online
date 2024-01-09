<?php

class Maintenance_commision_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get maintenance_commision by id
     */
    function get_maintenance_commision()
    {
        return $this->db->get('maintenance_commision')->row_array();
    }
        
    /*
     * function to add new maintenance_commision
     */
    function add_maintenance_commision($params)
    {
        $this->db->insert('maintenance_commision',$params);
        return true;
    }
    
    /*
     * function to update maintenance_commision
     */
    function update_maintenance_commision($id,$params)
    {
        return $this->db->update('maintenance_commision',$params);
    }

    function count_maintenance_commision()
    {
        return $this->db->get('maintenance_commision')->num_rows();
    }
  }