<div id="product-header">
    <section class="bg-theme-gradient breadcrumb-area">
        <div class="container">
            <div class="row">
                <div class="col-md-12 breadcrumb-contents">
                    <div class="pt-5 pb-5">
                        <h2 class="page-title">
                            Konfirmasi Pembayaran
                        </h2>
                    </div>
                </div>
                <!-- end /.col-md-12 -->
            </div>
            <!-- end /.row -->
        </div>
        <!-- end /.container -->
    </section>
</div>
<div class="clearfix"></div>
<div class="mt-4"></div>
<div id="checkout">
    <div class="container">
        <div class="row">

            <div class="col-lg-12 mt-3 form-shipping">
                <div class="bg-white border border-radius-10 p-4">
                    <?php $this->load->view('backoffice/partials/_alert');?>
                    <form action="<?=base_url('payment_confirmation/confirmation');?>" method="post" enctype="multipart/form-data">
                        <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
                        <div class="form-group">
                            <label for="">Order ID</label>
                            <input type="text" class="form-control form-search" placeholder="Order ID" name="order_id" required="required">
                        </div>
                        <div class="form-group">
                            <label for="">Jumlah Pembayaran</label>
                            <input type="number" class="form-control form-search" placeholder="Jumlah Pembayaran" name="amount" required="required">
                        </div>
                        <div class="form-group">
                            <label for="">Nama Bank (Misal : BCA)</label>
                            <input type="text" class="form-control form-search" placeholder="Nama Bank (Misal : BCA)" name="bank_name" required="required">
                        </div>
                        <div class="form-group">
                            <label for="">Nomor Rekening (Misal : 0982xxx)</label>
                            <input type="text" class="form-control form-search" placeholder="Nomor Rekening (Misal : 0982xxx)" name="bank_number" required="required">
                        </div>
                        <div class="form-group">
                            <label for="">Pemilik Rekening (Misal : Ipan)</label>
                            <input type="text" class="form-control form-search" placeholder="Pemilik Rekening (Misal : Ipan)" name="account_name" required="required">
                        </div>
                        <div class="form-group">
                            <label for="">Bukti Transfer</label>
                            <input type="file" class="form-control form-search" name="image" accept="image/*" required="required">
                        </div>
                        <div class="form-group">
                            <button type="submit" class="text-light btn btn-theme btn-theme-gradient btn-block btn-lg border-radius-none" id="btn-proses-pesanan">
                                Konfirmasi Pembayaran
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>