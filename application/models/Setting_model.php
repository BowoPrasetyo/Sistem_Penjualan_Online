<?php

 
class Setting_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get setting by id
     */
    function get_setting($id)
    {
        return $this->db->get_where('settings',array('id'=>$id))->row_array();
    }

    function get_setting_by_name($name)
    {
        return $this->db->get_where('settings',array('name'=>$name))->row_array();
    }
        
    /*
     * Get all settings
     */
    function get_all_settings()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('settings')->result_array();
    }
        
    /*
     * function to add new setting
     */
    function add_setting($params)
    {
        $this->db->insert('settings',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update setting
     */
    function update_setting($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('settings',$params);
    }

    function update_by_name($name,$value)
    {
        $this->db->where('name',$name);
        return $this->db->update('settings',[
            'value' => $value
        ]);
    }
    
    /*
     * function to delete setting
     */
    function delete_setting($id)
    {
        return $this->db->delete('settings',array('id'=>$id));
    }
}
