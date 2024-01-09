<?php

 
class Category_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get category by id
     */
    function get_category($id)
    {
        return $this->db->get_where('categories',array('id'=>$id))->row_array();
    }
        
    /*
     * Get all categories
     */
    function get_all_categories()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('categories')->result_array();
    }

    function get_all_categories_publish()
    {
        $this->db->order_by('id', 'desc');
        $this->db->where('status','publish');
        return $this->db->get('categories')->result_array();
    }

    function get_all_categories_with_count()
    {
        $this->db->select('*, (SELECT count(id) from products WHERE category_id = categories.id AND categories.status ="publish" AND stock > 0 AND status = "publish") as total_products');
        $this->db->order_by('id', 'desc');
        return $this->db->get('categories')->result_array();
    }
        
    /*
     * function to add new category
     */
    function add_category($params)
    {
        $this->db->insert('categories',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update category
     */
    function update_category($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('categories',$params);
    }
    
    /*
     * function to delete category
     */
    function delete_category($id)
    {
        return $this->db->delete('categories',array('id'=>$id));
    }

    function datatable() {
        $this->datatables->select('
            categories.id,
            categories.name,
            categories.icon,
        '
        );

        
        $this->datatables->from('categories');
        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."backoffice/category/edit/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-edit'></i> Ubah</a>", 'id');
        return $this->datatables->generate();
    }

    public function pagination($limit = 10, $start = 0, $path = '')
    {
        $offset =  $start == 0 ? 0 : ($start + $limit) - 1;
        $query = $this->db
        ->limit($limit, $offset);

        if ($sort = $this->input->get('sort')) {
        list($sortCol, $sortDir) = explode('|', $sort);
        $query->order_by($sortCol, $sortDir);
        } else {
        $query->order_by('x1.created_at', 'DESC');
        }
        
        if ($q = $this->input->get('q')) {
        $query->like('x1.name', $q);
        }

    
        $data = $query->get('categories x1')
        ->result();

        $total = $this->countTotal();

        $currentPage = (int) $start + 1;
        $totalPage = ceil($total / $limit);
        $nextPage = ($currentPage + 1) > $totalPage ? null : "{$path}?page=" . ($currentPage + 1);

        return [
        'success' => true,
        'message' => 'Success Get categories',
        'current_page' => $currentPage,
        'data' => $data,
        'first_page_url' => "{$path}?page=1",
        'from' => $total - $currentPage,
        'last_page' => $totalPage,
        'last_page_url' => "{$path}?page=$totalPage",
        'next_page_url' => $nextPage,
        'path' => $path,
        'per_page' => $limit,
        'prev_page_url' => "{$path}?page=" . ($currentPage - 1),
        'to' => $total - $currentPage,
        'total' => $total
        ];
    }

  public function countTotal($status = null)
  {
    $query =  $this->db;

    return $query->get('categories')->num_rows();
  }
}
