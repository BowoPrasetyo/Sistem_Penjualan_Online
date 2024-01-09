<?php

class Product_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get product by id
     */
    function get_product($id)
    {
        return $this->db->get_where('products',array('id'=>$id))->row_array();
    }

    function findById($id)
    {
        return $this->db->get_where('products',array('id'=>$id))->row();
    }

    function findByIds($id)
    {
        return $this->db->where_in('id', $id)->get('products')->result();;
    }

    function findBySlug($slug)
    {
        $this->db->select("
            products.id, 
            products.category_id, 
            products.title,
            products.slug,
            products.description,
            products.image,
            products.video,
            products.weight,
            products.long,
            products.width,
            products.height,
            products.price,
            products.stock,
            products.view,
            products.product_ref,
            categories.name as category_name,
        ");
        $this->db->join('categories', 'products.category_id=categories.id');
        return $this->db->get_where('products',array('slug'=>$slug))->row();
    }

    function getAllBy($limit,$start,$search,$col,$dir, $where =[])
    {
        $this->db->select("products.*")->from("products");

        $this->db->limit($limit,$start)->order_by($col,$dir);
        if(!empty($search)){
            foreach($search as $key => $value){
                $this->db->like($key,$value);    
            }   
        }
        $this->db->where($where);  
        $result = $this->db->get();
        if($result->num_rows()>0)
        {
            return $result->result();  
        }
        else
        {
            return null;
        }
    }

    function getCountAllBy($limit,$start,$search,$order,$dir, $where = [])
    { 
        $this->db->select("products.*")->from("products");  
        if(!empty($search)){
            foreach($search as $key => $value){
                $this->db->like($key,$value);    
            }   
        }
        $this->db->where($where);
        $result = $this->db->get();
        return $result->num_rows();
    } 
        
    /*
     * Get all products
     */
    function get_all_products()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('products')->result_array();
    }

    function get_all_valid_products()
    {
        $this->db->select('products.*, (SELECT image from product_images where product_ref = products.product_ref and is_thumbnail = 1 limit 1) as image');
        // $this->db->or_where('product_images.is_thumbnail', 1);
        // $this->db->or_where('product_images.is_thumbnail', NULL);
        $this->db->where('stock >', 0);
        $this->db->where('status', 'publish');
        $this->db->limit(12);
        $this->db->order_by('id', 'desc');
        return $this->db->get('products')->result_array();
    }

    function get_search_valid_products($search = null, $category = null)
    {
        $this->db->select('products.*, (SELECT image from product_images where product_ref = products.product_ref and is_thumbnail = 1 limit 1) as image');
        // $this->db->or_where('product_images.is_thumbnail', 1);
        // $this->db->or_where('product_images.is_thumbnail', NULL);
        $this->db->where('stock >', 0);
        $this->db->where('status', 'publish');

        if($search != null) {
            $this->db->like('title', $search);
        }

        if($category != null) {
            $this->db->where('category_id', $category);
        }

        $this->db->limit(15);
        $this->db->order_by('id', 'desc');
        return $this->db->get('products')->result_array();
    }
        
    /*
     * function to add new product
     */
    function add_product($params)
    {
        $this->db->insert('products',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update product
     */
    function update_product($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('products',$params);
    }
    
    /*
     * function to delete product
     */
    function delete_product($id)
    {
        return $this->db->delete('products',array('id'=>$id));
    }

    function datatable() {
        $this->datatables->select('
            products.id,
            products.category_id, 
            products.title,
            products.slug,
            products.description,
            products.image,
            products.video,
            products.weight,
            products.long,
            products.width,
            products.height,
            products.price,
            products.stock,
            products.view,
            products.product_ref,
        '
        );

        
        $this->datatables->from('products');
        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."backoffice/product/edit/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-edit'></i> Ubah</a>", 'id');
        return $this->datatables->generate();
    }

    public function pagination($limit = 10, $start = 0, $path = '')
    {
        $offset =  $start == 0 ? 0 : ($start + $limit) - 1;
        $query = $this->db
        ->select('x1.*, x2.name as category_name')
        ->join('categories x2', 'x1.category_id=x2.id', 'LEFT_JOIN')
        ->limit($limit, $offset);

        if ($sort = $this->input->get('sort')) {
        list($sortCol, $sortDir) = explode('|', $sort);
        $query->order_by($sortCol, $sortDir);
        } else {
        $query->order_by('x1.created_at', 'DESC');
        }
        
        if ($q = $this->input->get('q')) {
        $query->like('x1.title', $q);
        }

    
        $data = $query->get('products x1')
        ->result();

        $total = $this->countTotal();

        $currentPage = (int) $start + 1;
        $totalPage = ceil($total / $limit);
        $nextPage = ($currentPage + 1) > $totalPage ? null : "{$path}?page=" . ($currentPage + 1);

        return [
        'success' => true,
        'message' => 'Success Get Products',
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

    if($status != null) {
      $query->where('is_active', $status);
    }

    return $query->get('products')->num_rows();
  }
}
