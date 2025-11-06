"""
Sample Excel Generator for Jain University Events
This script creates a template Excel file with sample data
"""

import pandas as pd
from datetime import datetime, timedelta
import os

def create_sample_excel():
    """Generate sample Excel file with proper formatting"""
    
    # Sample data
    data = {
        'event_name': [
            'Introduction to Python Programming',
            'Advanced Web Development Workshop',
            'AI & Machine Learning Symposium',
            'Leadership Development Training',
            'Tech Career Fair 2024',
            'Physics Research Conference',
            'Digital Marketing Seminar',
            'Cloud Computing Bootcamp',
            'Environmental Science Competition',
            'Student Innovation Hackathon',
            'Business Ethics Workshop',
            'Entrepreneurship Conclave',
            'Cybersecurity Awareness Webinar',
            'Mobile App Development Training',
            'Data Science Masterclass',
            'Artificial Intelligence Summit',
            'Software Testing Workshop',
            'DevOps and CI/CD Training',
            'UI/UX Design Conference',
            'Blockchain Technology Seminar'
        ],
        'description': [
            'Learn Python basics, syntax, and fundamental programming concepts with hands-on exercises',
            'Master HTML5, CSS3, JavaScript, React, and modern web development practices',
            'Explore artificial intelligence, machine learning algorithms, and real-world applications',
            'Develop leadership skills, team management, and organizational effectiveness',
            'Connect with top tech companies for internship and placement opportunities',
            'Showcase latest research in physics and discuss cutting-edge discoveries',
            'Understand digital marketing strategies, SEO, SEM, and social media marketing',
            'Intensive training on AWS, Azure cloud platforms, and cloud infrastructure',
            'Participate in competitive environmental science challenges and case studies',
            'Build innovative projects and compete with fellow students for prizes',
            'Discuss ethical business practices, corporate responsibility, and compliance',
            'Network with entrepreneurs and learn about startup development',
            'Learn cybersecurity threats, prevention strategies, and best practices',
            'Develop Android and iOS applications from scratch to production',
            'Advanced data analysis, visualization, and business intelligence techniques',
            'Deep dive into AI technologies, neural networks, and practical implementations',
            'Quality assurance methodologies, automation testing, and tools',
            'Continuous integration, continuous deployment, and DevOps practices',
            'Modern UI/UX principles, design thinking, and user experience optimization',
            'Understanding blockchain, cryptocurrencies, and distributed systems'
        ],
        'school': [
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Humanities and Social Sciences',
            'School of Computer Science and Engineering',
            'School of Sciences',
            'School of Commerce',
            'School of Computer Science and Engineering',
            'School of Sciences',
            'School of Computer Science and Engineering',
            'CMS Business School',
            'CMS Business School',
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Computer Science and Engineering',
            'School of Design, Media and Creative Arts',
            'School of Computer Science and Engineering'
        ],
        'department': [
            'Department of Computer Science and Engineering',
            'Department of Computer Science and Engineering',
            'Department of Information Science and Engineering',
            'Department of Humanities & Social Sciences',
            'Department of Computer Science and Engineering',
            'Department of Physics and Electronics',
            'Department of Commerce',
            'Department of Information Science and Engineering',
            'Department of Biotechnology and Genetics',
            'Department of Computer Science and Engineering',
            'Department of Management Studies',
            'Department of Management Studies',
            'Department of Information Science and Engineering',
            'Department of Computer Science and Engineering',
            'Department of Data Analytics and Mathematical Science',
            'Department of Information Science and Engineering',
            'Department of Computer Science and Engineering',
            'Department of Information Science and Engineering',
            'Department of Design',
            'Department of Computer Science and Engineering'
        ],
        'event_type': [
            'Workshop',
            'Workshop',
            'Symposium',
            'Training',
            'Competition',
            'Conference',
            'Seminar',
            'Training',
            'Competition',
            'Competition',
            'Workshop',
            'Seminar',
            'Webinar',
            'Training',
            'Workshop',
            'Conference',
            'Workshop',
            'Training',
            'Conference',
            'Seminar'
        ],
        'venue': [
            'Computer Lab - Block A',
            'Auditorium A',
            'Convention Center',
            'Training Room 101',
            'Main Campus Ground',
            'Physics Lab - Block B',
            'Business School Hall',
            'IT Lab - Block C',
            'Science Building',
            'Computer Lab - Block A',
            'Business School Hall',
            'Convention Center',
            'Online - Zoom',
            'IT Lab - Block C',
            'Data Science Lab',
            'Convention Center',
            'Computer Lab - Block A',
            'IT Lab - Block C',
            'Design Studio',
            'Auditorium A'
        ],
        'event_date': [
            (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=8)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=10)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=12)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=15)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=18)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=20)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=22)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=25)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=28)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=32)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=35)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=37)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=40)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=42)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=45)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=48)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=50)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=52)).strftime('%Y-%m-%d')
        ],
        'end_date': [
            (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=8)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=11)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=12)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=15)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=19)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=20)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=23)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=25)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=28)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=32)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=35)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=38)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=40)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=43)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=45)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=49)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=50)).strftime('%Y-%m-%d'),
            (datetime.now() + timedelta(days=53)).strftime('%Y-%m-%d')
        ],
        'event_action': [
            'workshop',
            'training',
            'symposium',
            'training',
            'competition',
            'conference',
            'seminar',
            'bootcamp',
            'competition',
            'hackathon',
            'workshop',
            'conclave',
            'webinar',
            'training',
            'masterclass',
            'summit',
            'workshop',
            'training',
            'conference',
            'seminar'
        ]
    }
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Create Excel file
    output_path = 'sample_events_template.xlsx'
    
    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Events', index=False)
        
        # Format the Excel sheet
        worksheet = writer.sheets['Events']
        
        # Set column widths
        column_widths = {
            'A': 30,  # event_name
            'B': 50,  # description
            'C': 40,  # school
            'D': 40,  # department
            'E': 15,  # event_type
            'F': 25,  # venue
            'G': 15,  # event_date
            'H': 15,  # end_date
            'I': 15   # event_action
        }
        
        for col, width in column_widths.items():
            worksheet.column_dimensions[col].width = width
    
    print(f"✅ Sample Excel file created: {output_path}")
    print(f"   Records: {len(df)}")
    print(f"   Path: {os.path.abspath(output_path)}")
    print("\n📋 File contains the following columns:")
    for col in df.columns:
        print(f"   - {col}")
    
    return output_path

if __name__ == '__main__':
    create_sample_excel()