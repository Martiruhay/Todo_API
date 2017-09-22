class CreateTodos < ActiveRecord::Migration[5.0]
  def change
    create_table :todos do |t|
      t.string :tile
      t.string :created_by

      t.timestamps
    end
  end
end
