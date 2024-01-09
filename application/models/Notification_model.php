<?php

 
class Notification_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get notifications by id
     */
    function get_notifications($id)
    {
        return $this->db->get_where('notifications',array('id'=>$id))->row_array();
    }

    function get_notifications_by_user($user)
    {
        $this->db->limit(10);
        return $this->db->order_by('id', 'desc')->get_where('notifications',array('user_id'=>$user))->result();
    }
        
    /*
     * Get all notificationss
     */
    function get_all_notificationss()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('notifications')->result_array();
    }
        
    /*
     * function to add new notifications
     */
    function add_notification($params)
    {
        $this->db->insert('notifications',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update notifications
     */
    function update_notification($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('notifications',$params);
    }
    
    /*
     * function to delete notifications
     */
    function delete_notification($id)
    {
        return $this->db->delete('notifications',array('id'=>$id));
    }
}
